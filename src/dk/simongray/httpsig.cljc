(ns dk.simongray.httpsig
  "HTTP Message Signatures by RFC 9421: sign a request or a response, and
  verify the signatures of one.

  A message is a request or response map like those of wary-fetch. A
  request has :method, :url, :headers and :body, and a response has
  :status, :headers and :body. Header names can be in any case. A header's
  value is text or a vector of texts, and the body is text, bytes or nil.
  You can hide any of these texts, and a key's PEM or secret, with
  wary-fetch's secret/hide.

  A key is a map with a :keyid, an :alg (one of algorithms) and the key
  material, one of these:

  - :pem, a key in PEM: SPKI or PKCS#8, or PKCS#1 and SEC1
  - :jwk, a JWK as a map
  - :secret, the bytes or the text of a shared secret for hmac-sha256
  - :key, a webcrypto-clj key, e.g. a CryptoKey that a page keeps
    unextractable

  Without an :alg, the algorithm follows from the kind of key, e.g.
  rsa-v1_5-sha256 for RSA as in Mastodon, and rsa-pss-sha512 for a key of
  RSASSA-PSS, which can't have another :alg. For verifying, a key map can
  also have the :public-pem of its private key, as generate-key returns
  it.

  The functions that sign and verify return values on the JVM and promises
  in ClojureScript, since WebCrypto only has promises. Chain them with
  wary-fetch's async/then to write code for both."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.httpsig.impl.async :as async]
            [dk.simongray.httpsig.impl.components :as components]
            [dk.simongray.httpsig.impl.date :as date]
            [dk.simongray.httpsig.impl.keys :as keys]
            [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.httpsig.impl.sfv :as sfv]
            [dk.simongray.wary-fetch.async :as wary-async]
            [dk.simongray.wary-fetch.url :as wary-url]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]))

(def algorithms
  "The names of the algorithms in RFC 9421's registry (section 6.2.2). The
  library signs and verifies with all of them, though Ed25519 needs Java
  15 or later on the JVM."
  (set (clojure.core/keys keys/algorithms)))

(def default-options
  "The default of each option of sign and verify that has one:

  - :alg?, true: a new signature names its algorithm, which Mastodon
    ignores but Gancio's beta requires
  - :max-age-seconds, 3600: how long ago a signature's created can be, an
    hour as the SWICG report on the fediverse's signatures suggests
  - :max-skew-seconds, 300: how far ahead of the clock its created can be
  - :max-signatures, 3: how many of a message's signatures verify tries
  - :min-rsa-bits, 2048: the smallest RSA key that verify accepts
  - :algorithms, all of algorithms: the algorithms that verify accepts"
  {:alg?             true
   :max-age-seconds  3600
   :max-skew-seconds 300
   :max-signatures   3
   :min-rsa-bits     2048
   :algorithms       algorithms})

(defn- of-request
  "The component `component-name` of the request of a response, with the
  req parameter."
  [component-name]
  [component-name {"req" true}])

;; RFC 9421, section 7.3.3: a response that covers nothing of its request
;; can stand as the answer to any other
(defn- default-components
  "The components that a signature of the `message` covers unless the
  `opts` name others: @method and @target-uri of a request, or @status of
  a response, plus those of its request when `opts` have the :request.
  Both cover content-digest when the message has a body."
  [message opts]
  (cond-> (cond
            (not (components/response? message)) ["@method" "@target-uri"]
            (:request opts)                       ["@status" (of-request "@method") (of-request "@target-uri")]
            :else                                 ["@status"])
    (some? (:body message)) (conj "content-digest")))

(defn- covers?
  "Whether the component identifiers `ids` have one of the name
  `component-name`."
  [ids component-name]
  (some #(= component-name (first %)) ids))

(defn- with-covered-digest
  "The `message` with a Content-Digest of its body when the component
  identifiers `ids` cover one and it has none."
  [message ids]
  (cond-> message
    (and (covers? ids "content-digest")
         (nil? (message/field-lines (:headers message) "content-digest")))
    digest/with-content-digest))

;; RFC 9421, section 2.3
(defn- signature-params
  "The parameters of a new signature by the `key` with the algorithm `alg`,
  as pairs, in the order of the RFC's examples."
  [key alg {:keys [created expires nonce tag alg?] :as opts}]
  (let [created (if (some? created) created (date/now opts))]
    (cond-> []
      created      (conj ["created" (date/seconds created)])
      (:keyid key) (conj ["keyid" (:keyid key)])
      alg?         (conj ["alg" alg])
      expires      (conj ["expires" (date/seconds expires)])
      nonce        (conj ["nonce" nonce])
      tag          (conj ["tag" tag]))))

(defn- dictionary
  "The Dictionary of the field `field-name` of the `message`, or a throw
  when it doesn't parse."
  [message field-name]
  (if-let [lines (message/field-lines (:headers message) field-name)]
    (or (sfv/parse :dictionary lines)
        (throw (ex-info (str "The message's " field-name " isn't a Dictionary")
                        {:type ::malformed})))
    []))

;; RFC 9421, sections 4.1, 4.2 and 4.3
(defn- with-signature
  "The `message` with the `signature` of the `label`, whose covered
  components are `ids` and whose parameters are `params`, beside the
  signatures that it has."
  [message label ids params signature]
  (let [inputs     (dictionary message "signature-input")
        signatures (dictionary message "signature")]
    (when (some #(= label (first %)) (concat inputs signatures))
      (throw (ex-info (str "The message has a signature labelled " label " already")
                      {:type ::label-taken :label label})))
    (-> message
        (message/with-field "Signature-Input"
                            (sfv/serialize :dictionary (conj inputs [label [ids params]])))
        (message/with-field "Signature"
                            (sfv/serialize :dictionary (conj signatures [label [signature []]]))))))

;; RFC 9421, section 3.1
(defn sign
  "The `message` signed with the `key` by the `opts` below and
  default-options: the message with a Signature-Input and a Signature
  added (in ClojureScript a promise of it).

  Unless :components says otherwise, a request's signature covers both
  its @method and its @target-uri, and a response's covers its @status.
  With :request, a response also covers the method and the URL of the
  request (as @method and @target-uri with the req parameter), so that
  nobody can pass it off as the answer to another request. Both cover
  content-digest when the message has a body.

  It adds a Content-Digest when it covers one and the message has none.
  It also rewrites a request's URL as each platform's client sends it, so
  that @target-uri is the URL on the wire.

  The `opts` are these:

  - :components, the covered components in order, each a name (e.g.
    \"@authority\" or \"content-type\"), or a pair of a name and a map of
    its parameters, e.g. [\"@query-param\" {\"name\" \"Pet\"}]
  - :label, the signature's label, sig1 by default
  - :created, an inst (the time now by default), or false for none
  - :expires, an inst
  - :nonce and :tag, texts
  - :alg?, whether the signature names its algorithm
  - :request, the request that a response answers, for components with
    req
  - :field-types, the type of each structured field (e.g. {\"example-dict\"
    :dictionary}) for components with sf
  - :now-fn, a function that returns the time now

  It throws an ex-info with a :type for a message that it can't sign, e.g.
  ::missing-component for a covered field that the message lacks."
  ([message key]
   (sign message key {}))
  ([message key opts]
   (async/promised
    (fn []
      (let [opts    (merge default-options opts)
            message (components/with-legal-url message)
            ids     (mapv components/identifier
                          (or (:components opts) (default-components message opts)))
            message (with-covered-digest message ids)]
        (wary-async/then
         (keys/signing-key key)
         (fn [{:keys [alg] :as signer}]
           (let [params (signature-params key alg opts)
                 base   (components/signature-base message ids params opts)]
             (wary-async/then
              (webcrypto/sign (:sign (get keys/algorithms alg)) (:key signer) (bytes/encode base))
              #(with-signature message (:label opts "sig1") ids params %))))))))))

(defn- params-data
  "The signature parameters `params` as a map with keywords for their
  names, and insts for created and expires."
  [params]
  (into {} (for [[k v] params]
             [(keyword k) (if (and (#{"created" "expires"} k) (integer? v))
                            (date/instant v)
                            v)])))

(defn- component-data
  "The component identifier `id` as a name, or a pair of its name and a map
  of its parameters."
  [[component-name params :as id]]
  (if (empty? params)
    component-name
    [component-name (into {} params)]))

;; RFC 9421, sections 4.1 and 4.2
(defn- read-signature
  "The signature labelled `label` of the Signature-Input `member` and the
  Signature `value`, as a map of its :label, its covered :components as
  identifiers, its :params as pairs and its :signature as bytes, or a map
  with an :error when it's malformed."
  [label member value]
  (let [[items params] member
        [signature]    value]
    (if (and (vector? items)
             (every? #(string? (first %)) items)
             (bytes/bytes? signature))
      {:label label :components items :params params :signature signature}
      {:label label :error ::malformed})))

(defn- read-signatures
  "The signatures of the `message` as read-signature returns them, in the
  order of its Signature-Input, or a map of the :error when it has none or
  they don't parse."
  [message]
  (let [input-lines (message/field-lines (:headers message) "signature-input")
        inputs      (sfv/parse :dictionary input-lines)
        values      (some->> (message/field-lines (:headers message) "signature")
                             (sfv/parse :dictionary)
                             (into {}))]
    (cond
      (nil? input-lines)               {:error ::unsigned}
      (or (nil? inputs) (nil? values)) {:error ::malformed}
      :else                            (or (seq (for [[label member] inputs
                                                      :when (contains? values label)]
                                                  (read-signature label member (get values label))))
                                           {:error ::malformed}))))

(defn signatures
  "The well-formed signatures of the `message` in order, without verifying
  them, e.g. to read a keyid before verify. Each is a map of its :label,
  :components, :params (by keyword, with insts for created and expires)
  and its :signature as bytes."
  [message]
  (let [found (read-signatures message)]
    (if (map? found)
      []
      (vec (for [{:keys [error] :as signature} found
                 :when (not error)]
             (-> signature
                 (update :components #(mapv component-data %))
                 (update :params params-data)))))))

;; RFC 9421, section 2.3
(def ^:private param-types
  "The type of the value of each signature parameter."
  {"created" integer?
   "expires" integer?
   "keyid"   string?
   "alg"     string?
   "nonce"   string?
   "tag"     string?})

(defn- malformed-params?
  "Whether the signature `params` have values of the wrong types."
  [params]
  (some (fn [[k v]] (when-let [type? (param-types k)] (not (type? v)))) params))

(defn- uncovered
  "The first component that the `opts` require a signature of the
  `message` to cover and that its covered `ids` lack, or nil.

  The :required-components of `opts` replace the default policy. In that,
  a request covers @method and its whole URL: @target-uri, or @authority
  with @request-target or with both @path and @query. A response covers
  its @status, and with the :request of `opts` the same of the request,
  with the req parameter. Both cover content-digest when the message has
  a body."
  [message ids opts]
  (let [covered   (set (map components/same-identifier ids))
        has?      #(contains? covered (components/same-identifier (components/identifier %)))
        response? (components/response? message)
        ;; the components of the request: its own, or with req in a response
        of        (if response? of-request identity)
        request?  (or (not response?) (some? (:request opts)))]
    (if-let [required (:required-components opts)]
      (first (remove has? required))
      (cond
        (and response? (not (has? "@status")))
        "@status"

        (and request? (not (has? (of "@method"))))
        (of "@method")

        ;; @path alone would leave the query to anyone who changes it
        (and request?
             (not (has? (of "@target-uri")))
             (not (and (has? (of "@authority"))
                       (or (has? (of "@request-target"))
                           (and (has? (of "@path")) (has? (of "@query")))))))
        (of "@target-uri")

        (and (message/has-body? message) (not (has? "content-digest")))
        "content-digest"))))

;; RFC 9421, section 3.2.1
(defn- freshness-error
  "The :error of the signature `params` by the clock and the `opts`, or nil
  when it's fresh: created at most :max-age-seconds ago and at most
  :max-skew-seconds ahead, and not expired."
  [params {:keys [max-age-seconds max-skew-seconds] :as opts}]
  (let [t       (date/seconds (date/now opts))
        created (sfv/value-of params "created")
        expires (sfv/value-of params "expires")]
    (cond
      (nil? created)                                   ::not-covered
      (> (- t created) max-age-seconds)                ::expired
      (> (- created t) max-skew-seconds)               ::not-yet-valid
      (and expires (> (- t max-skew-seconds) expires)) ::expired)))

(defn- digest-error
  "The error of the Content-Digest of the `message` when the covered
  component `ids` include it, as a map, or nil."
  [message ids]
  (when (covers? ids "content-digest")
    (case (:error (digest/verify message))
      nil              nil
      ::digest/missing {:error ::missing-component :component "content-digest"}
      {:error ::digest-mismatch})))

(defn- error-of
  "The result of calling `f`, or the error of the ex-info that it throws,
  as a map of the :error and the :component that it names."
  [f]
  (try
    (f)
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
      (let [id (:component (ex-data e))]
        (cond-> {:error (async/error-type e)}
          id (assoc :component (component-data id)))))))

(defn- identifier-error
  "The error of the first of the covered component `ids` of a signature of
  the `message` that RFC 9421 doesn't allow, as a map, or nil."
  [message ids]
  (error-of #(run! (fn [id] (components/check-identifier id (components/response? message))) ids)))

(defn- failure
  "The result of the `signature` that fails with the `error`, a map of the
  :error and maybe the :component."
  [{:keys [label params] :as signature} error]
  (merge {:label label :keyid (sfv/value-of params "keyid")} error))

(defn- policy-error
  "The first error of the `signature` of the `message` that shows without
  its key, as a map, or nil. Each check runs only when those before it
  pass."
  [message {:keys [components params] :as signature} opts]
  (some->> (or (some->> (:error signature) (hash-map :error))
               (when (malformed-params? params) {:error ::malformed})
               (identifier-error message components)
               (some->> (uncovered message components opts)
                        (hash-map :error ::not-covered :component))
               (some->> (freshness-error params opts) (hash-map :error))
               (digest-error message components))
           (failure signature)))

(defn- key-params
  "The parameters of the `signature` that a key function takes."
  [{:keys [label params] :as signature}]
  (assoc (params-data params) :label label))

(defn- key-error
  "The :error of the key `verifier` (a map of its :alg and :key) for the
  `signature` by the `opts`, or nil."
  [{:keys [alg] :as verifier} {:keys [params] :as signature} opts]
  (let [named (sfv/value-of params "alg")]
    ;; RFC 9421, section 3.2, step 6.5, and section 7.3.6
    (if (and named (not= named alg))
      ::wrong-algorithm
      (keys/policy-error verifier opts))))

(defn- result-of
  "The result of a verified `signature` with the key map `key` that the
  `verifier` imported."
  [{:keys [label components params] :as signature} key {:keys [alg] :as verifier}]
  (merge {:label      label
          :alg        alg
          :key        (keys/shown key)
          :components (mapv component-data components)}
         (select-keys (params-data params) [:keyid :created :expires :nonce :tag])))

(defn- verified
  "The result of verifying the `signature` with the signature base `base`
  and the key map `key`, as a map with an :error when it fails."
  [signature base key opts]
  (if (nil? key)
    (failure signature {:error ::unknown-key})
    (wary-async/then
     (async/attempt #(keys/verifying-key key))
     (fn [{verifier :value e :error}]
       (if-let [error (if e (keys/import-error e) (key-error verifier signature opts))]
         (failure signature {:error error})
         (wary-async/then
          (async/attempt #(webcrypto/verify (:sign (get keys/algorithms (:alg verifier)))
                                            (:key verifier)
                                            (:signature signature)
                                            (bytes/encode base)))
          (fn [{:keys [value]}]
            (if (true? value)
              (result-of signature key verifier)
              (failure signature {:error ::invalid-signature})))))))))

(defn- check-signature
  "The result of verifying the `signature` of the `message` with the key
  that `key-fn` returns for it, by the `opts`."
  [message key-fn signature opts]
  (let [error (policy-error message signature opts)
        base  (when-not error
                (error-of #(components/signature-base message (:components signature)
                                                      (:params signature) opts)))]
    (cond
      error       error
      (map? base) (failure signature base)
      :else       (wary-async/then (key-fn (key-params signature))
                                   #(verified signature base % opts)))))

(defn- first-verified
  "The first result of verifying the `signatures` in turn with `check` that
  has no :error, or else the first result."
  [check signatures]
  (letfn [(step [[signature & more] first-error]
            (wary-async/then (check signature)
                             (fn [result]
                               (cond
                                 (not (:error result)) result
                                 (seq more)            (step more (or first-error result))
                                 :else                 (or first-error result)))))]
    (step signatures nil)))

(defn- picked
  "The signatures of `found` that the :label, :tag and :max-signatures of
  `opts` pick."
  [found {:keys [label tag max-signatures]}]
  (cond->> found
    label (filter #(= label (:label %)))
    tag   (filter #(= tag (sfv/value-of (:params %) "tag")))
    true  (take max-signatures)))

;; RFC 9421, section 3.2
(defn verify
  "The result of verifying a signature of the `message` with the key that
  `key-fn` returns for it, by the `opts` below and default-options (in
  ClojureScript a promise of it).

  The `key-fn` takes the parameters of a signature as a map of its :label,
  :keyid, :alg, :created, :expires, :nonce and :tag, and returns a key map
  (or nil, or a future or a promise of either). Return nil for a key that
  you don't know or trust.

  It tries at most :max-signatures of the message's signatures, in order.
  For the first that verifies, the result is a map of its :label, :keyid,
  :alg, :created, :expires, :nonce and :tag, its covered :components, and
  the :key that verified it. That key has no private key or secret, so
  that a log can show it.

  When none verifies, the result has the :error of the first, its :label
  and :keyid when it has them, and the :component that the error is
  about, if any. The error is one of these:

  - ::unsigned, for a message without a signature that the options pick
  - ::malformed, for fields or parameters that RFC 9421 doesn't allow
  - ::not-covered, for a component or a created that the policy needs
  - ::missing-component, for a covered component that the message lacks,
    or whose value can't go in a signature base
  - ::expired and ::not-yet-valid, for a signature outside its time
  - ::digest-mismatch, for a body that doesn't match its covered digest
  - ::unknown-key, when `key-fn` returns no key
  - ::invalid-key, for a key that doesn't import or is too small
  - ::unsupported-algorithm, for an algorithm that the platform lacks
  - ::wrong-algorithm, for an alg that doesn't match the key or isn't one
    of the :algorithms
  - ::invalid-signature, for a signature that doesn't verify

  The `opts` are those of default-options, and these:

  - :label, to verify the signature of this label alone
  - :tag, to verify the signatures with this tag alone
  - :required-components, the components that a signature has to cover,
    in place of the default policy: a request covers @method and its
    whole URL, as @target-uri, or as @authority with @request-target or
    with both @path and @query. A response covers its @status, and with
    :request the same of the request, with the req parameter. Both cover
    content-digest when the message has a body.
  - :request, the request that a response answers, for components with
    req
  - :field-types, as sign takes them
  - :now-fn, a function that returns the time now

  It doesn't check a nonce for replays, since that needs a store: check
  the :nonce of the result against your own."
  ([message key-fn]
   (verify message key-fn {}))
  ([message key-fn opts]
   (async/promised
    (fn []
      (let [opts   (merge default-options opts)
            found  (read-signatures message)
            chosen (when-not (map? found) (picked found opts))]
        (cond
          (map? found)    found
          (empty? chosen) {:error ::unsigned}
          :else           (first-verified #(check-signature message key-fn % opts) chosen)))))))

(defn- params-pairs
  "The signature parameters `params`, a map or pairs with names as strings
  or keywords, as pairs of RFC 9421's terms."
  [params]
  (vec (for [[k v] (sfv/pairs params)]
         [(name k) (if (inst? v) (date/seconds v) v)])))

;; RFC 9421, section 2.5
(defn signature-base
  "The signature base of the `message` for a signature that covers the
  `components` with the `params`, by the `opts`: the text that the
  signature signs.

  The components are those that sign takes, and the `params` a map or
  pairs of their names and values, e.g. {:created #inst \"…\" :keyid \"k\"}.
  The `opts` are the :request and :field-types that sign takes. It throws
  ::missing-component or ::malformed when it can't make the base."
  ([message components params]
   (signature-base message components params {}))
  ([message components params opts]
   (components/signature-base message (mapv components/identifier components)
                              (params-pairs params) opts)))

;; RFC 9421, sections 2.1 and 2.2
(defn component
  "The value of the component `id` of the `message`, by the :request and
  :field-types of `opts`, as sign takes them.

      (component {:url \"https://Example.com:443/a?b\"} \"@authority\")
      ;; => \"example.com\""
  ([message id]
   (component message id {}))
  ([message id opts]
   (components/component-value message (components/identifier id) opts)))

;; RFC 9421, section 5.1
(defn accept-signature
  "The value of an Accept-Signature field that asks for the signatures in
  `requests`, by label. Each is a map of the :components to cover and the
  :params to include, e.g.

      {\"sig1\" {:components [\"@method\"]
                :params     {:keyid \"k\" :created true}}}

  A parameter of true asks the signer to choose its value."
  [requests]
  (sfv/serialize :dictionary
                 (for [[label {:keys [components params]}] (sfv/pairs requests)]
                   [label [(mapv components/identifier components) (params-pairs params)]])))

(def ^:private signature-fields
  "The fields that a signer adds to a request, in lower case. Each hop of
  a redirect needs them anew."
  #{"signature" "signature-input" "content-digest" "digest"})

(defn- unsigned
  "The `request` without the fields that a signature added to it, and with
  its :query-params in its URL, as wary-fetch sends it."
  [{:keys [query-params] :as request}]
  (cond-> (update request :headers
                  (fn [headers]
                    (into {} (remove #(contains? signature-fields (str/lower-case (name (key %)))))
                          headers)))
    query-params (-> (update :url wary-url/with-query query-params)
                     (dissoc :query-params))))

;; A server that redirects elsewhere picks the URL of the next hop, so a
;; signature for any URL that it likes, with the body of a 307 or a 308,
;; would make the sender its signing oracle. Mastodon signs every hop, but
;; this sender signs a hop to another origin only for a GET or a HEAD.
(defn- signs-hop?
  "Whether a sender signs the `hop` of a redirect of the `request`: one to
  the same origin, or a GET or a HEAD."
  [request hop]
  (or (wary-url/same-origin? (:url request) (:url hop))
      (contains? #{"GET" "HEAD"} (str/upper-case (components/method-name hop)))))

;; The double knock of the fediverse: the next signer after a 400 or a 401
(defn sender
  "A function like wary-fetch's send! that signs each request with the
  `key` and sends it with `send`, by the `opts` below and those of sign.

      (def send-signed!
        (sender http/send! actor-key))

  It tries each of :signers in turn (sign by default): when the server
  answers 400 or 401, it sends the request again, signed by the next one.
  For the fediverse, [cavage/sign sign] sends draft-cavage first and RFC
  9421 next, as Mastodon does. It sends a request to any URL but an http
  or https one unsigned, e.g. one to a Nostr relay.

  A signature covers the URL, so each hop of a redirect needs its own. The
  sender adds a :prepare-fn to the request, which wary-fetch calls to sign
  each hop before sending it. It signs a hop to another origin only when
  it's a GET or a HEAD, so that a server can't redirect a signed POST to a
  URL of its choosing. A browser follows its own redirects, so there only
  the first hop has a signature."
  ([send key]
   (sender send key {}))
  ([send key opts]
   (let [signers (:signers opts [sign])]
     (fn [request]
       (if-not (contains? #{"http" "https"} (wary-url/scheme (:url request)))
         (send request)
         (letfn [(knock [[signer & more]]
                   (let [sign-hop (fn [hop]
                                    (let [hop (unsigned hop)]
                                      (if (signs-hop? request hop)
                                        (signer hop key opts)
                                        hop)))]
                     (wary-async/then
                      (signer (unsigned request) key opts)
                      (fn [signed]
                        (wary-async/then
                         (send (assoc signed :prepare-fn sign-hop))
                         (fn [response]
                           (if (and (contains? #{400 401} (:status response)) (seq more))
                             (knock more)
                             response)))))))]
           (knock signers)))))))

(defn generate-key
  "A new key map of the algorithm `alg` with the `keyid` (in ClojureScript
  a promise of it). An HMAC key has a :secret, and any other a :pem and
  the :public-pem to publish, e.g. in an actor document. The secret and
  the private PEM are hidden with wary-fetch's secret/hide, so they print
  as #<secret>.

      (generate-key \"rsa-v1_5-sha256\" \"https://example.com/actor#main-key\")"
  [alg keyid]
  (async/promised #(keys/generate-key alg keyid)))

(comment
  (def k
    (generate-key "ed25519" "test"))

  (def signed
    (sign {:method :post :url "https://example.com/inbox" :body "{}"} k))

  (verify signed (constantly k))
  (signatures signed)
  #_.)
