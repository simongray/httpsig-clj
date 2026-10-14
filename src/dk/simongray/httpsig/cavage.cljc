(ns dk.simongray.httpsig.cavage
  "Signatures of draft-cavage-http-signatures, as the fediverse signs and
  verifies them: the Signature field that Mastodon and the servers that
  talk to it send.

  The fediverse uses a profile of the draft that no version describes
  exactly: RSA-SHA256 over a few headers, with a little of the twelfth and
  last version (from 2019), such as hs2019 and (created). This namespace
  has that profile alone. Its keys, results and errors are those of the
  root namespace, and so is its sync or async: values on the JVM, and
  promises in ClojureScript.

  Every server of the fediverse takes these signatures, and only some take
  those of RFC 9421. To sign for both, give httpsig/sender the :signers
  [sign httpsig/sign]."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.impl.async :as async]
            [dk.simongray.httpsig.impl.components :as components]
            [dk.simongray.httpsig.impl.date :as date]
            [dk.simongray.httpsig.impl.keys :as keys]
            [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.httpsig.impl.sfv :as sfv]
            [dk.simongray.wary-fetch.async :as wary-async]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]
            [dk.simongray.whatwg-url :as url]))

(def default-options
  "The default of each option of sign and verify that has one, beside those
  of httpsig/default-options:

  - :algorithm, \"rsa-sha256\": the name that a signature by an RSA key
    gives its algorithm, as Mastodon, Misskey and WordPress send it, where
    GoToSocial, Lemmy and Forgejo send hs2019
  - :query?, true: (request-target) has the query of the URL, as Mastodon
    signs it"
  {:algorithm "rsa-sha256"
   :query?    true})

;; RFC 3230, section 4.3.2, as Mastodon writes it
(defn digest
  "The value of a Digest field of RFC 3230 for the `body` (text as UTF-8,
  bytes or nil): its SHA-256 in base64, after SHA-256=."
  [body]
  (str "SHA-256=" (bytes/base64 (hash/digest :sha-256 (message/body-bytes body)))))

(defn- now
  "The time now as an inst, by the :now-fn of `opts` when it has one."
  [opts]
  (if-let [now-fn (:now-fn opts)]
    (now-fn)
    #?(:clj (java.util.Date.) :cljs (js/Date.))))

(defn- seconds
  "The whole seconds of the inst `t` since the epoch."
  [t]
  (quot (inst-ms t) 1000))

(defn- request-target
  "The value of (request-target) of the `message`: its method in lower case
  and its path, with the query when `query?`."
  [message query?]
  (let [u (url/parse (str (:url message)))]
    (str (str/lower-case (components/method-name message)) " " (url/pathname u)
         (when (and query? (some? (:query u))) (str "?" (:query u))))))

(defn- missing
  "The exception of the header `header-name` that the message lacks."
  [header-name]
  (ex-info (str "The message has no " header-name)
           {:type ::httpsig/missing-component :component header-name}))

;; draft-cavage-http-signatures-12, section 2.3
(defn- header-value
  "The value of the header `header-name` of the `message` in a signing
  string, with the signature `params` and the `opts` of sign."
  [message header-name params {:keys [query?]}]
  (case header-name
    "(request-target)" (request-target message query?)
    "(created)"        (str (or (:created params) (throw (missing header-name))))
    "(expires)"        (str (or (:expires params) (throw (missing header-name))))
    (let [lines (message/field-lines (:headers message) header-name)]
      (cond
        lines                 (str/join ", " (map components/canonical-line lines))
        ;; a client sets the Host of the URL itself
        (= "host" header-name) (url/host (str (:url message)))
        :else                 (throw (missing header-name))))))

(defn signing-string
  "The text that a signature over the `headers` of the `message` signs,
  e.g. [\"(request-target)\" \"host\" \"date\"], with the signature `params`
  :created and :expires as seconds, and the :query? of `opts`.

  A Host that the message lacks comes from its URL, since every client
  sets that Host itself."
  ([message headers]
   (signing-string message headers {} {}))
  ([message headers params opts]
   (let [opts (merge default-options opts)]
     (str/join "\n" (for [h headers]
                      (str h ": " (header-value message (str/lower-case h) params opts)))))))

(defn- signature-field
  "The value of the Signature field of the `signature` by the key map `key`
  with the `algorithm` name over the `headers`, with the `params`."
  [key algorithm headers {:keys [created expires]} signature]
  (str/join "," (cond-> [(str "keyId=\"" (:keyid key) "\"")
                         (str "algorithm=\"" algorithm "\"")]
                  created (conj (str "created=" created))
                  expires (conj (str "expires=" expires))
                  true    (conj (str "headers=\"" (str/join " " headers) "\"")
                                (str "signature=\"" (bytes/base64 signature) "\"")))))

(defn- signed-headers
  "The headers that a signature of the `message` covers unless the options
  give others: (request-target), host and date, and digest when it has a
  body."
  [message]
  (cond-> ["(request-target)" "host" "date"]
    (some? (:body message)) (conj "digest")))

(defn- algorithm-name
  "The name of the algorithm of a signature by a key of the algorithm `alg`
  of RFC 9421 over the `headers`, by the :algorithm of `opts`. Only RSA
  keys sign as rsa-sha256, and the draft and Mastodon take (created) and
  (expires) only with hs2019."
  [alg headers opts]
  (if (and (= "rsa-v1_5-sha256" alg)
           (not-any? #{"(created)" "(expires)"} headers))
    (:algorithm opts)
    "hs2019"))

;; draft-cavage-http-signatures-12, sections 2.4 and 4.1
(defn sign
  "The `message` signed with the `key` by the `opts` below, as the message
  with a Signature field (or in ClojureScript a promise of it).

  It signs (request-target), host and date, and digest when the message
  has a body, unless :signed-headers says otherwise. It adds the Date and
  the Digest that a signed header needs. The URL of a request is written
  as the client of each platform sends it. A browser's fetch forbids a
  Date field, so this works on the JVM and in Node alone.

  The `opts` are those of default-options, and these:

  - :signed-headers, the headers to sign in order, of the message or among
    (request-target), (created) and (expires)
  - :created and :expires, insts for (created) and (expires), the time now
    by default for created
  - :now-fn, a function that gives the time now"
  ([message key]
   (sign message key {}))
  ([message key opts]
   (async/promised
    (fn []
      (let [opts    (merge default-options opts)
            message (components/with-legal-url message)
            headers (mapv str/lower-case (or (:signed-headers opts) (signed-headers message)))
            covers? #(some #{%} headers)
            absent? #(nil? (message/field-lines (:headers message) %))
            message (cond-> message
                      (and (covers? "date") (absent? "date"))
                      (message/with-field "Date" (date/imf-fixdate (now opts)))

                      (and (covers? "digest") (absent? "digest"))
                      (message/with-field "Digest" (digest (:body message))))
            params  (cond-> {}
                      (covers? "(created)") (assoc :created (seconds (or (:created opts) (now opts))))
                      (covers? "(expires)") (assoc :expires (seconds (or (:expires opts) (throw (missing "(expires)"))))))]
        (wary-async/then
         (keys/signing-key key)
         (fn [{:keys [alg] :as signer}]
           (wary-async/then
            (webcrypto/sign (:sign (get keys/algorithms alg)) (:key signer)
                            (bytes/encode (signing-string message headers params opts)))
            #(message/with-field message "Signature"
                                 (signature-field key (algorithm-name alg headers opts)
                                                  headers params %))))))))))

(def param-pattern
  "A parameter of a Signature field: a name, and a value in quotes or bare,
  before a comma or the end."
  #"\s*([A-Za-z]+)\s*=\s*(?:\"([^\"]*)\"|([^\s,\"]*))\s*(?:,|$)")

(defn- seconds-of
  "The whole seconds of the text `s` of a timestamp, or nil when it isn't
  one. The draft allows a decimal in expires."
  [s]
  (when (and s (re-matches #"-?\d+(\.\d+)?" s))
    (long #?(:clj (Double/parseDouble s) :cljs (js/parseFloat s)))))

;; draft-cavage-http-signatures-12, sections 2.1 and 2.2
(defn- read-signature
  "The Signature field `s` as a map of its :keyid, :algorithm, :headers,
  :signature as bytes, and :created and :expires as seconds, or of an
  :error when it's malformed.

  As Mastodon does, it takes a Signature prefix that old libraries of Node
  wrote, and refuses a parameter given twice."
  [s]
  (let [pairs  (re-seq param-pattern (str/replace s #"^\s*Signature\s+" ""))
        names  (map second pairs)
        values (into {} (for [[_ k quoted bare] pairs] [k (or quoted bare)]))
        alg    (get values "algorithm")
        heads  (if-let [h (get values "headers")]
                 (str/split (str/lower-case (str/trim h)) #"\s+")
                 ;; section 2.1.6, and date for rsa-sha256 as Mastodon has it
                 (if (or (nil? alg) (= "hs2019" alg)) ["(created)"] ["date"]))]
    (cond
      (or (empty? pairs) (not= (count names) (count (distinct names))))
      {:error ::httpsig/malformed}

      (or (nil? (get values "keyId"))
          (nil? (some-> (get values "signature") bytes/from-base64))
          (= [""] heads))
      {:error ::httpsig/malformed :keyid (get values "keyId")}

      :else
      {:keyid     (get values "keyId")
       :algorithm alg
       :headers   heads
       :signature (bytes/from-base64 (get values "signature"))
       :created   (seconds-of (get values "created"))
       :expires   (seconds-of (get values "expires"))})))

(defn- uncovered
  "The first header that the policy of `opts` requires a signature of the
  `message` over the `headers` to cover, and that it doesn't, or nil.

  The :required-headers of `opts` are those that it requires. By default
  they're Mastodon's: date or (created), (request-target) or digest, host
  for a GET and digest for a POST."
  [message headers opts]
  (let [covers? #(some #{%} headers)
        method  (components/method-name message)]
    (if-let [required (:required-headers opts)]
      (first (remove covers? (map str/lower-case required)))
      (cond
        (not (or (covers? "date") (covers? "(created)")))             "date"
        (not (or (covers? "(request-target)") (covers? "digest")))    "(request-target)"
        (and (= "GET" method) (not (covers? "host")))                 "host"
        (and (= "POST" method) (not (covers? "digest")))              "digest"))))

(defn- freshness-error
  "The :error of a signature over the `headers` of the `message`, with its
  :created and :expires, by the clock and the `opts`, or nil when it's
  fresh. Its time is its (created) when it covers one, and else its Date."
  [message {:keys [headers created expires]} {:keys [max-age-seconds max-skew-seconds] :as opts}]
  (let [t    (seconds (now opts))
        time (if (some #{"(created)"} headers)
               created
               (some-> (message/field-lines (:headers message) "date") first date/parse seconds))]
    (cond
      (nil? time)                      ::httpsig/malformed
      (> (- t time) max-age-seconds)   ::httpsig/expired
      (> (- time t) max-skew-seconds)  ::httpsig/not-yet-valid
      (and (some #{"(expires)"} headers) expires (> (- t max-skew-seconds) expires))
      ::httpsig/expired)))

;; RFC 3230, section 4.3.2: digests by algorithm, the names in any case
(defn- digest-error
  "The :error of the Digest of the `message` when a signature covers it, or
  nil when it has a SHA-256 or SHA-512 that matches its body and none that
  doesn't."
  [message]
  (let [b       (message/body-bytes (:body message))
        digests (for [line  (message/field-lines (:headers message) "digest")
                      entry (str/split line #",")
                      :let  [[_ alg value] (re-matches #"\s*([A-Za-z0-9-]+)=(\S+)\s*" entry)
                             hash-alg (get {"sha-256" :sha-256 "sha-512" :sha-512}
                                           (some-> alg str/lower-case))]
                      :when hash-alg]
                  (some-> (bytes/from-base64 value) (bytes/same? (hash/digest hash-alg b))))]
    (when (or (empty? digests) (some not digests))
      ::httpsig/digest-mismatch)))

(defn- policy-error
  "The first error of the `signature` of the `message` that the library
  finds before it looks for a key, as a keyword, or nil."
  [message {:keys [algorithm headers] :as signature} opts]
  (or (:error signature)
      (when-not (contains? #{nil "rsa-sha256" "hs2019"} algorithm)
        ::httpsig/wrong-algorithm)
      (when (uncovered message headers opts)
        ::httpsig/not-covered)
      (freshness-error message signature opts)
      (when (some #{"digest"} headers)
        (digest-error message))))

(defn- key-error
  "The :error of the key `verifier` (a map of its :alg and :key) for the
  `signature` by the `opts`, or nil."
  [{:keys [alg key]} {:keys [algorithm]} {:keys [algorithms min-rsa-bits]}]
  (let [bits (keys/modulus-bits key)]
    (cond
      ;; section 2.1.3: a named algorithm that disagrees with the key fails
      (and (= "rsa-sha256" algorithm) (not= "rsa-v1_5-sha256" alg)) ::httpsig/wrong-algorithm
      (not (contains? algorithms alg))                              ::httpsig/wrong-algorithm
      (and bits (< bits min-rsa-bits))                              ::httpsig/invalid-key)))

(defn- verifies?
  "Whether the `signature` of the `message` verifies with the key
  `verifier` over the signing string with or without the query of the URL,
  since Mobilizon and Pleroma sign the path alone (in ClojureScript a
  promise of it)."
  [message {:keys [headers created expires signature]} {:keys [alg key]} opts]
  (let [params  {:created created :expires expires}
        attempt (fn [query?]
                  (wary-async/then
                   (async/attempt #(webcrypto/verify (:sign (get keys/algorithms alg)) key signature
                                                     (bytes/encode (signing-string message headers params
                                                                                   (assoc opts :query? query?)))))
                   #(true? (:value %))))]
    (wary-async/then (attempt true)
                     (fn [verified]
                       (if (or verified (not (some #{"(request-target)"} headers)))
                         verified
                         (attempt false))))))

(defn- verified
  "The result of verifying the `signature` of the `message` with the key
  map `key`."
  [message signature key opts]
  (let [failure #(hash-map :keyid (:keyid signature) :error %)]
    (if (nil? key)
      (failure ::httpsig/unknown-key)
      (wary-async/then
       (async/attempt #(keys/verifying-key key))
       (fn [{verifier :value e :error}]
         (cond
           e
           (failure (if (= ::httpsig/unsupported-algorithm (async/error-type e))
                      ::httpsig/unsupported-algorithm
                      ::httpsig/invalid-key))

           (key-error verifier signature opts)
           (failure (key-error verifier signature opts))

           :else
           (wary-async/then (verifies? message signature verifier opts)
                            #(if %
                               (cond-> {:keyid      (:keyid signature)
                                        :alg        (:alg verifier)
                                        :key        key
                                        :components (:headers signature)}
                                 (:created signature) (assoc :created (sfv/instant (:created signature)))
                                 (:expires signature) (assoc :expires (sfv/instant (:expires signature))))
                               (failure ::httpsig/invalid-signature)))))))))

;; draft-cavage-http-signatures-12, section 2.5
(defn verify
  "The result of verifying the Signature field of the `message` with the
  key that `key-fn` gives for it, by the `opts` below (or in ClojureScript
  a promise of it).

  The `key-fn` takes the parameters of the signature as a map of its
  :keyid and :algorithm, and returns a key map (or nil, or a future or a
  promise of either), as httpsig/verify takes it. The key decides the
  algorithm, so hs2019 is RSA-SHA256 for an RSA key, as the fediverse
  reads it, and Ed25519 for an Ed25519 key, which GoToSocial tries too.

  The result is a map like that of httpsig/verify, whose :components are
  the signed headers, and the errors are the same. The verifier takes:

  - rsa-sha256, hs2019 or no algorithm at all
  - (request-target) with or without the query, since Mobilizon and
    Pleroma sign the path alone
  - (created) and (expires), and a Signature prefix as old libraries of
    Node wrote it
  - a Digest whose SHA-256 or SHA-512 matches the body, when it's signed

  The `opts` are those of httpsig/default-options and default-options, and
  these:

  - :required-headers, the headers that a signature has to cover, in place
    of Mastodon's: date or (created), (request-target) or digest, host for
    a GET and digest for a POST
  - :now-fn, a function that gives the time now

  The signature's time is its (created) when it covers one, and else its
  Date, which has to be IMF-fixdate."
  ([message key-fn]
   (verify message key-fn {}))
  ([message key-fn opts]
   (async/promised
    (fn []
      (let [opts  (merge httpsig/default-options default-options opts)
            lines (message/field-lines (:headers message) "signature")]
        (if (nil? lines)
          {:error ::httpsig/unsigned}
          (let [signature (read-signature (first lines))]
            (if-let [error (policy-error message signature opts)]
              {:keyid (:keyid signature) :error error}
              (wary-async/then (key-fn (select-keys signature [:keyid :algorithm]))
                               #(verified message signature % opts))))))))))

(comment
  (def k
    (httpsig/generate-key "rsa-v1_5-sha256" "https://example.com/actor#main-key"))

  (def signed
    (sign {:method :post :url "https://example.social/inbox" :body "{}"} k))

  (verify signed (constantly k))
  #_.)
