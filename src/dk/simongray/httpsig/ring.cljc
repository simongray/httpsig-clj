(ns dk.simongray.httpsig.ring
  "Signed Ring requests, for a server: the verification of a request as a
  function, e.g. for a Pedestal interceptor, and as middleware.

  A Ring request keeps the parts of its URL under separate keys and its
  body in a stream. So before they verify a signed request, the functions
  here turn it into a message with its whole URL and its body read into
  bytes. The request goes on to the handler with a new stream of those
  bytes (the bytes in ClojureScript), so the handler can read the body
  again."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.cavage :as cavage]
            [dk.simongray.httpsig.impl.async :as async]
            [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.wary-fetch.async :as wary-async]
            [dk.simongray.webcrypto.bytes :as bytes])
  #?(:clj (:import [java.io ByteArrayInputStream InputStream])))

(def default-options
  "The default of each option of verified and wrap-verify that has one:

  - :cavage?, false: a request without a Signature-Input is unsigned, rather
    than checked as draft-cavage
  - :required?, false: an unsigned request reaches the handler
  - :max-bytes, 10 MB: the largest body that a request can have"
  {:cavage?   false
   :required? false
   :max-bytes (* 10 1024 1024)})

(defn- body-bytes
  "The `body` of a Ring request (a string, bytes, a stream or nothing) as a
  map of its :bytes, or of the :error of a body with more than `max-bytes`.
  In ClojureScript a stream is an error too, so a server there reads the
  body first."
  [body max-bytes]
  (let [b (cond
            (nil? body)    (bytes/of [])
            (string? body) (bytes/encode body)
            :else          #?(:clj  (if (bytes? body)
                                      body
                                      (.readNBytes ^InputStream body (int (inc max-bytes))))
                              :cljs (when (instance? js/Uint8Array body) body)))]
    (cond
      (nil? b)                        {:error ::httpsig/invalid-body}
      (> (bytes/length b) max-bytes)  {:error ::httpsig/too-large}
      :else                           {:bytes b})))

;; RFC 9110, section 7.2: a Host is a host and maybe a port. A Host with a
;; / or a ? in it would move the path of the URL that a signature covers.
(def ^:private host-pattern
  #"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::[0-9]{1,5})?")

(defn- origin
  "The origin that the client of the Ring `request` sent it to: the :origin
  of `opts`, or else its scheme and its Host (or its server's name and
  port). Nil for a Host that isn't a host and a port."
  [{:keys [scheme server-name server-port] :as request} opts]
  (let [scheme (str (name (or scheme :http)) "://")
        host   (some-> (message/field-lines (:headers request) "host") first)]
    (cond
      (:origin opts)                 (str/replace (:origin opts) #"/+$" "")
      (nil? host)                    (str scheme server-name
                                          (when-not (contains? #{80 443 nil} server-port)
                                            (str ":" server-port)))
      (re-matches host-pattern host) (str scheme host))))

(defn message
  "The Ring `request` as a message of the root namespace, with its body as
  `b`, the bytes of its body. Its URL has the :origin of `opts`, or else
  its scheme and its Host, and is nil when the Host isn't a host and a
  port. Behind a proxy that ends TLS, the URL that Ring sees isn't the one
  the client signed, so give the public origin there, e.g.
  https://example.com."
  [{:keys [request-method uri query-string headers] :as request} b opts]
  {:method  request-method
   :url     (some-> (origin request opts)
                    (str uri (when query-string (str "?" query-string))))
   :headers headers
   :body    b})

(defn- with-body
  "The Ring `request` with the bytes `b` as its body, a stream of them on
  the JVM."
  [request b]
  (assoc request :body #?(:clj (ByteArrayInputStream. ^bytes b) :cljs b)))

(defn verified
  "The Ring `request` with the result of verifying its signature with the
  key that `key-fn` gives, under ::httpsig/signature, and a body that the
  handler can read again (or in ClojureScript a promise of it).

  The result is that of httpsig/verify, or of cavage/verify for a request
  without a Signature-Input when :cavage?. A signed request whose body has
  more than :max-bytes has a result with the :error ::httpsig/too-large,
  and in ClojureScript one whose body is a stream ::httpsig/invalid-body.
  An unsigned request goes on as it came, without ::httpsig/signature and
  with its body unread. The `opts` are those of default-options,
  httpsig/verify and cavage/verify, and :origin, as message takes it."
  ([request key-fn]
   (verified request key-fn {}))
  ([request key-fn opts]
   (async/promised
    (fn []
      (let [opts   (merge default-options opts)
            has?   #(some? (message/field-lines (:headers request) %))
            verify (cond
                     (has? "signature-input")                 httpsig/verify
                     (and (:cavage? opts) (has? "signature")) cavage/verify)
            {b :bytes error :error} (when verify (body-bytes (:body request) (:max-bytes opts)))]
        (cond
          (nil? verify) request
          error         (assoc request ::httpsig/signature {:error error})
          :else         (wary-async/then (verify (message request b opts) key-fn opts)
                                         #(assoc (with-body request b) ::httpsig/signature %))))))))

(defn- refusal
  "The Ring response to a request whose signature has the `error`, or none
  when the :required? of `opts` asks for one, with the :accept-signature of
  `opts`, a value of an Accept-Signature field (RFC 9421, section 5) that
  says what to sign."
  [error opts]
  (if (= ::httpsig/too-large error)
    {:status 413 :headers {"Content-Type" "text/plain"} :body "The body is too large"}
    {:status  401
     :headers (cond-> {"Content-Type" "text/plain"}
                (:accept-signature opts) (assoc "Accept-Signature" (:accept-signature opts)))
     :body    (if error
                (str "The signature doesn't verify: " (name error))
                "The request needs a signature")}))

(defn- refusal-of
  "The refusal of the verified Ring `request` when its signature fails, or
  when it has none and :required? says it needs one, or else nil."
  [request opts]
  (let [{:keys [error] :as result} (::httpsig/signature request)]
    (when (or error (and (nil? result) (:required? (merge default-options opts))))
      (refusal error opts))))

(defn wrap-verify
  "Ring middleware that verifies the signature of each request with the key
  that `key-fn` gives, by the `opts` of verified, before the `handler`
  sees it.

  A request whose signature fails gets a 401, as does an unsigned request
  when :required?, and a signed request with a body over :max-bytes gets
  a 413. Give :accept-signature, the value of an Accept-Signature field,
  to say what to sign. Any other request reaches the handler with the
  result of its signature under ::httpsig/signature, or without one when
  it's unsigned.

  It has both arities of a Ring handler. In ClojureScript, where the
  verification gives a promise, use the asynchronous one, or take the
  promise of a response from the other."
  ([handler key-fn]
   (wrap-verify handler key-fn {}))
  ([handler key-fn opts]
   (fn
     ([request]
      (wary-async/then (verified request key-fn opts)
                       #(or (refusal-of % opts) (handler %))))
     ([request respond raise]
      (wary-async/then (async/attempt #(verified request key-fn opts))
                       (fn [{:keys [value error]}]
                         (cond
                           error                      (raise error)
                           (refusal-of value opts)    (respond (refusal-of value opts))
                           :else                      (handler value respond raise))))))))

(comment
  (def k
    (httpsig/generate-key "ed25519" "https://example.com/actor#main-key"))

  (def handler
    (wrap-verify (fn [request] {:status 200 :body (pr-str (::httpsig/signature request))})
                 (constantly k)
                 {:origin "https://example.com"}))

  (handler {:request-method :get :uri "/notes/1" :headers {"host" "example.com"}})
  #_.)
