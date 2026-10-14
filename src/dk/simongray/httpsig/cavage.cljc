(ns dk.simongray.httpsig.cavage
  "Signatures of draft-cavage-http-signatures, as the fediverse signs and
  verifies them: the Signature field that Mastodon and the servers that
  talk to it send.

  The fediverse uses a profile of the draft that no version describes
  exactly: RSA-SHA256 over a few headers, with a little of the twelfth and
  last version (from 2019), such as hs2019 and (created). This namespace
  has that profile alone. Its key maps, results and errors are those of
  the root namespace. Like those of the root namespace, its functions
  return values on the JVM and promises in ClojureScript.

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
  "The default of each option of sign and signing-string that has one:

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

(defn- missing
  "The exception of the header `header-name` that the message lacks."
  [header-name]
  (components/missing header-name (str "The message has no " header-name)))

(defn- request-target
  "The value of (request-target) of the `message`: its method in lower case
  and its path, with the query when `query?`."
  [message query?]
  (let [u (or (some-> (:url message) str url/parse)
              (throw (missing "(request-target)")))]
    (str (str/lower-case (components/method-name message)) " " (url/pathname u)
         (when (and query? (some? (:query u))) (str "?" (:query u))))))

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
  with the :created and :expires of `params` in seconds and the :query? of
  `opts`.

  The headers are names in order, e.g. [\"(request-target)\" \"host\"
  \"date\"]. A Host that the message lacks comes from its URL, since every
  client sets that Host itself."
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

(defn- default-headers
  "The headers that a signature of the `message` covers unless the options
  give others: (request-target), host and date, and digest when it has a
  body."
  [message]
  (cond-> ["(request-target)" "host" "date"]
    (some? (:body message)) (conj "digest")))

(defn- with-signed-fields
  "The `message` with the Date and the Digest that the `headers` cover and
  it lacks, by the :now-fn of `opts`."
  [message headers opts]
  (let [covers? #(some #{%} headers)
        absent? #(nil? (message/field-lines (:headers message) %))]
    (cond-> message
      (and (covers? "date") (absent? "date"))
      (message/with-field "Date" (date/imf-fixdate (date/now opts)))

      (and (covers? "digest") (absent? "digest"))
      (message/with-field "Digest" (digest (:body message))))))

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
  has a body, unless :signed-headers says otherwise. It adds a Date and a
  Digest when it signs them and the message has none. It rewrites the URL
  of a request as each platform's client sends it. A browser's fetch
  forbids a Date field, so this works on the JVM and in Node alone.

  The `opts` are those of default-options, and these:

  - :signed-headers, the headers to sign in order, of the message or among
    (request-target), (created) and (expires)
  - :created and :expires, insts for (created) and (expires), the time now
    by default for created
  - :now-fn, a function that returns the time now

  It throws ::httpsig/invalid-key for a keyid with a quote, a backslash
  or a line break, which the draft can't write."
  ([message key]
   (sign message key {}))
  ([message key opts]
   (async/promised
    (fn []
      ;; the draft writes the keyId in quotes, without escapes
      (when (re-find #"[\"\\\r\n]" (str (:keyid key)))
        (throw (keys/invalid-key "A keyId has no quotes, backslashes or line breaks")))
      (let [opts    (merge default-options opts)
            headers (mapv str/lower-case (or (:signed-headers opts) (default-headers message)))
            message (-> (components/with-legal-url message)
                        (with-signed-fields headers opts))
            covers? #(some #{%} headers)
            params  (cond-> {}
                      (covers? "(created)")
                      (assoc :created (date/seconds (or (:created opts) (date/now opts))))

                      (covers? "(expires)")
                      (assoc :expires (date/seconds (or (:expires opts)
                                                        (throw (missing "(expires)"))))))]
        (wary-async/then
         (keys/signing-key key)
         (fn [{:keys [alg] :as signer}]
           (wary-async/then
            (webcrypto/sign (:sign (get keys/algorithms alg)) (:key signer)
                            (bytes/encode (signing-string message headers params opts)))
            #(message/with-field message "Signature"
                                 (signature-field key (algorithm-name alg headers opts)
                                                  headers params %))))))))))

(defn- tchars-end
  "The index after the tchars of HTTP from `i` in the text `s`."
  [s i]
  (if (sfv/tchar? (sfv/code-at s i))
    (recur s (inc i))
    i))

(defn- read-value
  "The value of a parameter at `i` in the text `s`, a token or a quoted
  string, and the index after it."
  [s i]
  (if (= 0x22 (sfv/code-at s i))
    (sfv/parse-string s i)
    (let [end (tchars-end s i)]
      (when (= i end)
        (throw (sfv/invalid "A parameter has a value")))
      [(subs s i end) end])))

;; draft-cavage-http-signatures-12, section 4.1, as Mastodon's parser reads
;; it: parameters apart by commas, each a token, = and a token or a quoted
;; string. A loop rather than a regex, which would backtrack through a long
;; run of letters at each of them.
(defn- read-params
  "The parameters of the Signature field `s` as pairs of names and values,
  or a throw when they don't parse."
  [s]
  (loop [i     (sfv/skip s 0 sfv/ows)
         pairs []]
    (let [name-end    (tchars-end s i)
          _           (when (= i name-end)
                        (throw (sfv/invalid "A parameter has a name")))
          equals      (sfv/expect s (sfv/skip s name-end sfv/ows) 0x3D
                                  "A parameter's name goes before =")
          [value end] (read-value s (sfv/skip s equals sfv/ows))
          pairs       (conj pairs [(subs s i name-end) value])
          after       (sfv/skip s end sfv/ows)]
      (cond
        (= -1 (sfv/code-at s after))   pairs
        (= 0x2C (sfv/code-at s after)) (recur (sfv/skip s (inc after) sfv/ows) pairs)
        :else                          (throw (sfv/invalid "Parameters are apart by commas"))))))

(defn- seconds-of
  "The whole seconds of the text `s` of a timestamp, or nil when it isn't
  one. The draft allows a decimal in expires."
  [s]
  (when (and s (re-matches #"-?\d{1,15}(\.\d+)?" s))
    (long (parse-double s))))

;; draft-cavage-http-signatures-12, sections 2.1 and 2.2
(defn- read-signature
  "The Signature field `s` as a map of its :keyid, :algorithm, :headers,
  :signature as bytes, and :created and :expires as seconds, or of an
  :error when it's malformed.

  As Mastodon does, it takes a Signature prefix that old libraries of Node
  wrote, and refuses a parameter given twice. It refuses a header signed
  twice too, which no signer needs."
  [s]
  (let [pairs     (try (read-params (str/replace s #"^\s*Signature\s+" ""))
                       (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) _
                         nil))
        names     (map first pairs)
        values    (into {} pairs)
        alg       (get values "algorithm")
        signature (some-> (get values "signature") bytes/from-base64)
        headers   (if-let [h (get values "headers")]
                    (str/split (str/lower-case (str/trim h)) #"\s+")
                    ;; section 2.1.6, and date for rsa-sha256 as Mastodon has it
                    (if (or (nil? alg) (= "hs2019" alg)) ["(created)"] ["date"]))]
    (cond
      (or (nil? pairs) (not= (count names) (count (distinct names))))
      {:error ::httpsig/malformed}

      (or (nil? (get values "keyId"))
          (nil? signature)
          (= [""] headers)
          (not= (count headers) (count (distinct headers))))
      {:error ::httpsig/malformed :keyid (get values "keyId")}

      :else
      {:keyid     (get values "keyId")
       :algorithm alg
       :headers   headers
       :signature signature
       :created   (seconds-of (get values "created"))
       :expires   (seconds-of (get values "expires"))})))

(defn- uncovered
  "The first header that the policy of `opts` requires a signature of the
  `message` over the `headers` to cover, and that it doesn't, or nil.

  The :required-headers of `opts` are those that it requires. By default
  they're Mastodon's, and a little more: date or (created), and
  (request-target) or digest. Every method but POST needs host, where
  Mastodon asks it of a GET, and a message with a body needs digest,
  where Mastodon asks it of a POST."
  [message headers opts]
  (let [covers? #(some #{%} headers)
        method  (str/upper-case (components/method-name message))]
    (if-let [required (:required-headers opts)]
      (first (remove covers? (map str/lower-case required)))
      (cond
        (not (or (covers? "date") (covers? "(created)")))          "date"
        (not (or (covers? "(request-target)") (covers? "digest"))) "(request-target)"
        (and (not= "POST" method) (not (covers? "host")))         "host"
        (and (message/has-body? message) (not (covers? "digest"))) "digest"))))

(defn- freshness-error
  "The error of a signature over the `headers` of the `message`, with its
  :created and :expires, by the clock and the `opts`, as a map, or nil
  when it's fresh. Its time is its (created) when it covers one, and else
  its Date."
  [message {:keys [headers created expires]} {:keys [max-age-seconds max-skew-seconds] :as opts}]
  (let [t        (date/seconds (date/now opts))
        created? (some #{"(created)"} headers)
        line     (when-not created? (first (message/field-lines (:headers message) "date")))
        time     (if created? created (some-> line date/parse date/seconds))]
    (cond
      (and (not created?) (nil? line)) {:error ::httpsig/missing-component :component "date"}
      (nil? time)                      {:error ::httpsig/malformed}
      (> (- t time) max-age-seconds)   {:error ::httpsig/expired}
      (> (- time t) max-skew-seconds)  {:error ::httpsig/not-yet-valid}
      (and (some #{"(expires)"} headers) expires (> (- t max-skew-seconds) expires))
      {:error ::httpsig/expired})))

;; RFC 3230, section 4.3.2: digests by algorithm, the names in any case
(defn- digest-error
  "The error of the Digest of the `message` when a signature covers it, as
  a map, or nil when it has a SHA-256 or SHA-512 that matches its body and
  none that doesn't."
  [message]
  (let [b       (message/body-bytes (:body message))
        lines   (message/field-lines (:headers message) "digest")
        digests (for [line  lines
                      entry (str/split line #",")
                      :let  [[_ alg value] (re-matches #"\s*([A-Za-z0-9-]+)=(\S+)\s*" entry)
                             hash-alg (get {"sha-256" :sha-256 "sha-512" :sha-512}
                                           (some-> alg str/lower-case))]
                      :when hash-alg]
                  (some-> (bytes/from-base64 value) (bytes/same? (hash/digest hash-alg b))))]
    (cond
      (nil? lines)                             {:error ::httpsig/missing-component :component "digest"}
      (or (empty? digests) (some not digests)) {:error ::httpsig/digest-mismatch})))

(defn- policy-error
  "The first error of the `signature` of the `message` that the library
  finds before it looks for a key, as a map of the :error and maybe the
  :component, or nil."
  [message {:keys [algorithm headers] :as signature} opts]
  (or (some->> (:error signature) (hash-map :error))
      (when-not (contains? #{nil "rsa-sha256" "hs2019"} algorithm)
        {:error ::httpsig/wrong-algorithm})
      (some->> (uncovered message headers opts)
               (hash-map :error ::httpsig/not-covered :component))
      (freshness-error message signature opts)
      (when (some #{"digest"} headers)
        (digest-error message))))

(defn- signing-strings
  "The texts that the `signature` of the `message` can sign by the `opts`,
  or a map of the :error and the :component that keeps it from them. One
  has the query of the URL, and for a GET or a HEAD another hasn't, since
  Mobilizon and Pleroma sign the path alone. A method that changes
  something has its query signed."
  [message {:keys [headers created expires]} opts]
  (try
    (let [reads? (contains? #{"GET" "HEAD"} (str/upper-case (components/method-name message)))]
      (into [] (distinct) (for [query? (if reads? [true false] [true])]
                            (signing-string message headers {:created created :expires expires}
                                            (assoc opts :query? query?)))))
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
      {:error (async/error-type e) :component (:component (ex-data e))})))

(defn- key-error
  "The :error of the key `verifier` (a map of its :alg and :key) for the
  `signature` by the `opts`, or nil."
  [{:keys [alg] :as verifier} {:keys [algorithm] :as signature} opts]
  ;; section 2.1.3: a named algorithm that disagrees with the key fails
  (if (and (= "rsa-sha256" algorithm) (not= "rsa-v1_5-sha256" alg))
    ::httpsig/wrong-algorithm
    (keys/policy-error verifier opts)))

(defn- verifies?
  "Whether the `signature` verifies with the key `verifier` over one of the
  signing `strings` (in ClojureScript a promise of it)."
  [{:keys [signature]} strings {:keys [alg key]}]
  (wary-async/some (fn [s]
                     (wary-async/then
                      (async/attempt #(webcrypto/verify (:sign (get keys/algorithms alg)) key signature
                                                        (bytes/encode s)))
                      #(true? (:value %))))
                   strings))

(defn- result-of
  "The result of a verified `signature` with the key map `key` that the
  `verifier` imported."
  [{:keys [keyid headers created expires] :as signature} key {:keys [alg] :as verifier}]
  (cond-> {:keyid      keyid
           :alg        alg
           :key        (keys/shown key)
           :components headers}
    created (assoc :created (date/instant created))
    expires (assoc :expires (date/instant expires))))

(defn- verified
  "The result of verifying the `signature` over one of the signing
  `strings` with the key map `key`."
  [signature strings key opts]
  (let [failure #(hash-map :keyid (:keyid signature) :error %)]
    (if (nil? key)
      (failure ::httpsig/unknown-key)
      (wary-async/then
       (async/attempt #(keys/verifying-key key))
       (fn [{verifier :value e :error}]
         (if-let [error (if e (keys/import-error e) (key-error verifier signature opts))]
           (failure error)
           (wary-async/then (verifies? signature strings verifier)
                            #(if %
                               (result-of signature key verifier)
                               (failure ::httpsig/invalid-signature)))))))))

;; draft-cavage-http-signatures-12, section 2.5
(defn verify
  "The result of verifying the Signature field of the `message` with the
  key that `key-fn` gives for it, by the `opts` below (or in ClojureScript
  a promise of it).

  The `key-fn` takes the parameters of the signature as a map of its
  :keyid and :algorithm (the draft's name, e.g. hs2019, rather than an
  :alg of RFC 9421), and returns a key map (or nil, or a future or a
  promise of either), as httpsig/verify takes it. The algorithm comes from
  the key: hs2019 means RSA-SHA256 for an RSA key (as the fediverse reads
  it) and Ed25519 for an Ed25519 key (which GoToSocial also tries).

  The result is a map like that of httpsig/verify, with the signed headers
  as its :components. The errors are the same. A signature can have:

  - rsa-sha256, hs2019 or no algorithm at all
  - for a GET or a HEAD, (request-target) with or without the query, since
    Mobilizon and Pleroma sign the path alone
  - (created) and (expires), and a Signature prefix as old libraries of
    Node wrote it
  - a Digest whose SHA-256 or SHA-512 matches the body, when it's signed

  The `opts` are those of httpsig/default-options, and these:

  - :required-headers, the headers that a signature has to cover, in place
    of the default: date or (created), (request-target) or digest, host
    for any method but POST, and digest for a message with a body
  - :now-fn, a function that returns the time now

  The signature's time is its (created) when it covers one, and else its
  Date, which has to be IMF-fixdate."
  ([message key-fn]
   (verify message key-fn {}))
  ([message key-fn opts]
   (async/promised
    (fn []
      (let [opts  (merge httpsig/default-options opts)
            lines (message/field-lines (:headers message) "signature")]
        (if (nil? lines)
          {:error ::httpsig/unsigned}
          (let [signature (read-signature (first lines))
                error     (policy-error message signature opts)
                strings   (when-not error (signing-strings message signature opts))]
            (if-let [error (or error (when (map? strings) strings))]
              (merge {:keyid (:keyid signature)} error)
              (wary-async/then (key-fn (select-keys signature [:keyid :algorithm]))
                               #(verified signature strings % opts))))))))))

(comment
  (def k
    (httpsig/generate-key "rsa-v1_5-sha256" "https://example.com/actor#main-key"))

  (def signed
    (sign {:method :post :url "https://example.social/inbox" :body "{}"} k))

  (verify signed (constantly k))
  #_.)
