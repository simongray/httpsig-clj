(ns dk.simongray.httpsig
  "HTTP Message Signatures by RFC 9421: sign a request or a response, and
  verify the signatures of one.

  A message is a request or a response map of wary-fetch. A request has
  :method, :url, :headers and :body, and a response has :status, :headers
  and :body. Header names can be in any case, and a value is text, a
  hidden text of wary-fetch, or a vector of them. The body is text, bytes,
  a hidden text or nil.

  A key is a map of its :keyid, its :alg (a name from algorithms) and its
  material, one of these:

  - :pem, the text of a key in PEM: SPKI or PKCS#8, or PKCS#1 and SEC1
  - :jwk, a JWK as a map
  - :secret, the bytes or the text of a shared secret for hmac-sha256
  - :key, a key of webcrypto-clj, e.g. a CryptoKey that a page keeps

  The material can be a hidden text. Without an :alg, the kind of key
  decides: RSA is rsa-v1_5-sha256, as in Mastodon. To verify, a key map can
  also have the :public-pem of its private key, as generate-key gives it.

  The functions that sign and verify return their results on the JVM (and
  promises of them in ClojureScript), since WebCrypto has only promises.
  Chain them with wary-fetch's async/then on both platforms."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.httpsig.impl.async :as async]
            [dk.simongray.httpsig.impl.components :as components]
            [dk.simongray.httpsig.impl.keys :as keys]
            [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.httpsig.impl.sfv :as sfv]
            [dk.simongray.wary-fetch.async :as wary-async]
            [dk.simongray.wary-fetch.url :as wary-url]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]))

(def algorithms
  "The names of the algorithms of RFC 9421's registry, section 6.2.2, all
  of which the library signs and verifies with. Ed25519 needs Java 15 or
  later on the JVM."
  (set (clojure.core/keys keys/algorithms)))

(def default-options
  "The default of each option of sign and verify that has one:

  - :alg?, true: a new signature names its algorithm, which Mastodon
    ignores but the beta of Gancio wants
  - :max-age-seconds, 3600: how old a signature can be by its created, an
    hour as the SWICG report on the fediverse's signatures suggests
  - :max-skew-seconds, 300: how far ahead of the clock its created can be
  - :max-signatures, 3: how many of a message's signatures verify tries
  - :min-rsa-bits, 2048: the smallest RSA key that verify takes
  - :algorithms, the algorithms that verify takes, all of algorithms"
  {:alg?             true
   :max-age-seconds  3600
   :max-skew-seconds 300
   :max-signatures   3
   :min-rsa-bits     2048
   :algorithms       algorithms})

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

(defn- default-components
  "The components that a signature of the `message` covers unless the
  options give others: @method and @target-uri of a request, or @status of
  a response, and content-digest when it has a body."
  [message]
  (cond-> (if (components/response? message) ["@status"] ["@method" "@target-uri"])
    (some? (:body message)) (conj "content-digest")))

(defn- covers?
  "Whether the component identifiers `ids` have one of the name
  `component-name`."
  [ids component-name]
  (some #(= component-name (first %)) ids))

;; RFC 9421, section 2.3
(defn- signature-params
  "The parameters of a new signature by the `key` with the algorithm `alg`,
  as pairs, in the order of the RFC's examples."
  [key alg {:keys [created expires nonce tag alg?] :as opts}]
  (let [created (if (some? created) created (now opts))]
    (cond-> []
      created      (conj ["created" (seconds created)])
      (:keyid key) (conj ["keyid" (:keyid key)])
      alg?         (conj ["alg" alg])
      expires      (conj ["expires" (seconds expires)])
      nonce        (conj ["nonce" nonce])
      tag          (conj ["tag" tag]))))

(defn- dictionary
  "The Dictionary of the field `field-name` of the `message`, or a throw
  when it doesn't parse."
  [message field-name]
  (if-let [lines (message/field-lines (:headers message) field-name)]
    (or (sfv/parse :dictionary (str/join ", " lines))
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
  default-options, as the message with a Signature-Input and a Signature
  (or in ClojureScript a promise of it).

  A request covers @method and @target-uri unless :components says
  otherwise, and a response @status, as well as content-digest when it has
  a body. A Content-Digest of the body is added when a covered
  content-digest needs it. The URL of a request is written as the client
  of each platform sends it, so that @target-uri is the URL on the wire.

  The `opts` are these:

  - :components, the covered components in order, each a name (e.g.
    \"@authority\" or \"content-type\"), or a pair of a name and a map of
    its parameters, e.g. [\"@query-param\" {\"name\" \"Pet\"}]
  - :label, of the signature, sig1 by default
  - :created, an inst, or false for none, the time now by default
  - :expires, an inst
  - :nonce and :tag, texts
  - :alg?, whether the signature names its algorithm
  - :request, the request of a response, for components with req
  - :field-types, the type of each structured field (e.g. {\"example-dict\"
    :dictionary}) for components with sf
  - :now-fn, a function that gives the time now

  It throws an ex-info with a :type for a message that it can't sign, e.g.
  ::missing-component for a covered field that the message lacks."
  ([message key]
   (sign message key {}))
  ([message key opts]
   (async/promised
    (fn []
      (let [opts    (merge default-options opts)
            message (components/with-legal-url message)
            ids     (mapv components/identifier (or (:components opts) (default-components message)))
            message (cond-> message
                      (and (covers? ids "content-digest")
                           (nil? (message/field-lines (:headers message) "content-digest")))
                      digest/with-content-digest)]
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
                            (sfv/instant v)
                            v)])))

(defn- component-data
  "The component identifier `id` as a name, or a pair of its name and a map
  of its parameters."
  [[component-name params]]
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
  "The signatures of the `message` as read-signature gives them, in the
  order of its Signature-Input, or a map of the :error when it has none or
  they don't parse."
  [message]
  (let [input-lines     (message/field-lines (:headers message) "signature-input")
        signature-lines (message/field-lines (:headers message) "signature")
        inputs          (some->> input-lines (str/join ", ") (sfv/parse :dictionary))
        values          (some->> signature-lines (str/join ", ") (sfv/parse :dictionary) (into {}))]
    (cond
      (nil? input-lines)                 {:error ::unsigned}
      (or (nil? inputs) (nil? values))   {:error ::malformed}
      :else                              (or (seq (for [[label member] inputs
                                                        :when (contains? values label)]
                                                    (read-signature label member (get values label))))
                                             {:error ::malformed}))))

(defn signatures
  "The signatures of the `message` that are well formed, in order, as maps
  of their :label, their :components, their :params (with keywords for
  their names, and insts for created and expires) and their :signature as
  bytes, e.g. to read a keyid before verify. It verifies nothing."
  [message]
  (let [found (read-signatures message)]
    (if (map? found)
      []
      (vec (for [{:keys [error] :as signature} found
                 :when (not error)]
             (-> signature
                 (update :components #(mapv component-data %))
                 (update :params params-data)))))))

(defn- param
  "The value of the signature parameter `k` in the `params`, as pairs."
  [params k]
  (some (fn [[pk v]] (when (= k pk) v)) params))

(defn- malformed-params?
  "Whether the signature `params` of RFC 9421, section 2.3, have values of
  the wrong types."
  [params]
  (or (some #(and (some? (param params %)) (not (integer? (param params %)))) ["created" "expires"])
      (some #(and (some? (param params %)) (not (string? (param params %)))) ["keyid" "alg" "nonce" "tag"])))

(defn- uncovered
  "The first component that the policy of `opts` requires the signature
  with the covered component `ids` of the `message` to cover, and that it
  doesn't, or nil.

  The :required-components of `opts` are those that it requires. By
  default a request covers @method and its whole URL: @target-uri, or
  @authority with @request-target or with both @path and @query. A
  response covers @status. Both cover content-digest when the message has
  a body."
  [message ids opts]
  (let [covered (set (map components/same-identifier ids))
        has?    #(contains? covered (components/same-identifier (components/identifier %)))]
    (if-let [required (:required-components opts)]
      (first (remove has? required))
      (cond
        (and (components/response? message) (not (has? "@status")))
        "@status"

        (and (not (components/response? message)) (not (has? "@method")))
        "@method"

        ;; @path alone would leave the query to anyone who changes it
        (and (not (components/response? message))
             (not (has? "@target-uri"))
             (not (and (has? "@authority")
                       (or (has? "@request-target") (and (has? "@path") (has? "@query"))))))
        "@target-uri"

        (and (message/has-body? message) (not (has? "content-digest")))
        "content-digest"))))

;; RFC 9421, section 3.2.1
(defn- freshness-error
  "The :error of the signature `params` by the clock and the `opts`, or nil
  when it's fresh: created at most :max-age-seconds ago and at most
  :max-skew-seconds ahead, and not expired."
  [params {:keys [max-age-seconds max-skew-seconds] :as opts}]
  (let [t       (seconds (now opts))
        created (param params "created")
        expires (param params "expires")]
    (cond
      (nil? created)                            ::not-covered
      (> (- t created) max-age-seconds)         ::expired
      (> (- created t) max-skew-seconds)        ::not-yet-valid
      (and expires (> (- t max-skew-seconds) expires)) ::expired)))

(defn- digest-error
  "The :error of the Content-Digest of the `message` when the signature
  with the covered component `ids` covers it, or nil."
  [message ids]
  (when (covers? ids "content-digest")
    (case (:error (digest/verify message))
      nil               nil
      ::digest/missing  ::missing-component
      ::digest-mismatch)))

(defn- identifier-error
  "The error of the first of the covered component `ids` of a signature of
  the `message` that RFC 9421 doesn't allow, as a map, or nil."
  [message ids]
  (try
    (run! #(components/check-identifier % (components/response? message)) ids)
    nil
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
      {:error (async/error-type e) :component (:component (ex-data e))})))

(defn- policy-error
  "The first error of the `signature` of the `message` that the library
  finds before it looks for a key, as a map, or nil. Each check runs only
  when those before it pass."
  [message {:keys [label components params] :as signature} opts]
  (when-let [error (or (some->> (:error signature) (hash-map :error))
                       (when (malformed-params? params) {:error ::malformed})
                       (identifier-error message components)
                       (some->> (uncovered message components opts)
                                (hash-map :error ::not-covered :component))
                       (some->> (freshness-error params opts) (hash-map :error))
                       (some->> (digest-error message components) (hash-map :error)))]
    (merge {:label label :keyid (param params "keyid")} error)))

(defn- signature-base-of
  "The signature base of the `signature` of the `message`, or a map of the
  :error that keeps it from one."
  [message {:keys [components params]} opts]
  (try
    (components/signature-base message components params opts)
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
      {:error (async/error-type e) :component (:component (ex-data e))})))

(defn- key-params
  "The parameters of the `signature` that a key function takes."
  [{:keys [label params]}]
  (assoc (params-data params) :label label))

(defn- key-error
  "The :error of the key `verifier` (a map of its :alg and :key) for the
  `signature` by the `opts`, or nil."
  [{:keys [alg key]} {:keys [params]} {:keys [algorithms min-rsa-bits]}]
  (let [named (param params "alg")
        bits  (keys/modulus-bits key)]
    (cond
      ;; RFC 9421, section 3.2, step 6.5, and section 7.3.6
      (and named (not= named alg))       ::wrong-algorithm
      (not (contains? algorithms alg))   ::wrong-algorithm
      (and bits (< bits min-rsa-bits))   ::invalid-key)))

(defn- result-of
  "The result of a verified `signature` with the key map `key` that the
  `verifier` imported."
  [{:keys [label components params]} key {:keys [alg]}]
  (merge {:label      label
          :alg        alg
          :key        (keys/shown key)
          :components (mapv component-data components)}
         (select-keys (params-data params) [:keyid :created :expires :nonce :tag])))

(defn- verified
  "The result of verifying the `signature` of the `message` with the base
  `base` and the key map `key`, as a map with an :error when it fails."
  [signature base key opts]
  (let [failure (fn [error] {:label (:label signature) :keyid (param (:params signature) "keyid") :error error})]
    (if (nil? key)
      (failure ::unknown-key)
      (wary-async/then
       (async/attempt #(keys/verifying-key key))
       (fn [{verifier :value e :error}]
         (cond
           e
           (failure (if (= ::unsupported-algorithm (async/error-type e)) ::unsupported-algorithm ::invalid-key))

           (key-error verifier signature opts)
           (failure (key-error verifier signature opts))

           :else
           (wary-async/then
            (async/attempt #(webcrypto/verify (:sign (get keys/algorithms (:alg verifier)))
                                              (:key verifier) (:signature signature) (bytes/encode base)))
            (fn [{:keys [value]}]
              (if (true? value)
                (result-of signature key verifier)
                (failure ::invalid-signature))))))))))

(defn- check-signature
  "The result of verifying the `signature` of the `message` with the key
  that `key-fn` gives for it, by the `opts`."
  [message key-fn signature opts]
  (let [error (policy-error message signature opts)
        base  (when-not error (signature-base-of message signature opts))]
    (cond
      error       error
      (map? base) (merge {:label (:label signature) :keyid (param (:params signature) "keyid")} base)
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

;; RFC 9421, section 3.2
(defn verify
  "The result of verifying a signature of the `message` with the key that
  `key-fn` gives for it, by the `opts` below and default-options (or in
  ClojureScript a promise of it).

  The `key-fn` takes the parameters of a signature as a map of its :label,
  :keyid, :alg, :created, :expires, :nonce and :tag, and returns a key map
  (or nil, or a future or a promise of either). Return nil for a key that
  you don't know or trust.

  The result of a signature that verifies is a map of its :label, :keyid,
  :alg, the :key that verified it (without a private key or a secret, so
  that a log can show it), its covered :components, and its :created,
  :expires, :nonce and :tag. One that doesn't has an :error and
  the :label and :keyid of the signature, when it has them. The error is
  one of these:

  - ::unsigned, for a message without a signature that the options pick
  - ::malformed, for fields or parameters that RFC 9421 doesn't allow
  - ::not-covered, for a component or a created that the policy needs
  - ::missing-component, for a covered component that the message lacks
  - ::expired and ::not-yet-valid, for a signature out of its time
  - ::digest-mismatch, for a body that doesn't match its covered digest
  - ::unknown-key, when `key-fn` gives no key
  - ::invalid-key, for a key that doesn't import, or too small
  - ::unsupported-algorithm, for one that the platform lacks
  - ::wrong-algorithm, for an alg that disagrees with the key, or isn't
    one of the :algorithms
  - ::invalid-signature, for a signature that doesn't verify

  The verifier tries the signatures in order, up to :max-signatures, and
  takes the first that verifies, or else the error of the first. The
  `opts` are those of default-options, and these:

  - :label, to verify the signature of this label alone
  - :tag, to verify the signatures with this tag alone
  - :required-components, the components that a signature has to cover,
    in place of the default policy: a request covers @method and its
    whole URL, as @target-uri, or as @authority with @request-target or
    with both @path and @query. A response covers its @status. Both cover
    content-digest when the message has a body.
  - :request, the request of a response, for components with req
  - :field-types, as sign takes them
  - :now-fn, a function that gives the time now

  A nonce isn't checked for replay, since that needs a store. Check the
  :nonce of the result in yours."
  ([message key-fn]
   (verify message key-fn {}))
  ([message key-fn opts]
   (async/promised
    (fn []
      (let [opts  (merge default-options opts)
            found (read-signatures message)]
        (if (map? found)
          found
          (let [picked (cond->> found
                         (:label opts) (filter #(= (:label opts) (:label %)))
                         (:tag opts)   (filter #(= (:tag opts) (param (:params %) "tag"))))]
            (if (empty? picked)
              {:error ::unsigned}
              (first-verified #(check-signature message key-fn % opts)
                              (take (:max-signatures opts) picked))))))))))

(defn- params-pairs
  "The signature parameters `params`, a map or pairs with names as strings
  or keywords, as pairs of RFC 9421's terms."
  [params]
  (vec (for [[k v] (sfv/pairs params)]
         [(name k) (if (inst? v) (seconds v) v)])))

;; RFC 9421, section 2.5
(defn signature-base
  "The signature base of a signature of the `message` that covers the
  `components` with the `params`, the text that the signature signs.

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
  "The value of an Accept-Signature field that asks for the signatures of
  `requests`, a map or pairs of a label and a map of the :components to
  cover and the :params to give, e.g. {\"sig1\" {:components [\"@method\"]
  :params {:keyid \"k\" :created true}}}. A parameter of true asks for one
  of the signer's choosing."
  [requests]
  (sfv/serialize :dictionary
                 (for [[label {:keys [components params]}] (sfv/pairs requests)]
                   [label [(mapv components/identifier components)
                           (vec (for [[k v] (sfv/pairs params)] [(name k) v]))]])))

(def ^:no-doc signature-fields
  "The fields that a signer adds to a request, which a hop of a redirect
  needs anew."
  ["Signature" "Signature-Input" "Content-Digest" "Digest"])

(defn- unsigned
  "The `request` without the fields that a signature added to it, and with
  its :query-params in its URL, as wary-fetch sends it."
  [{:keys [query-params] :as request}]
  (cond-> (update request :headers #(into {} (remove (fn [[k _]]
                                                       (some (fn [f] (message/field-name? (str/lower-case f) k))
                                                             signature-fields)))
                                              %))
    query-params (-> (update :url wary-url/with-query query-params)
                     (dissoc :query-params))))

(defn- web-request?
  "Whether the `request` goes to an http or https URL."
  [request]
  (contains? #{"http" "https"} (some-> (:url request) str (str/split #":" 2) first str/lower-case)))

;; A server that redirects elsewhere picks the URL of the next hop, so a
;; signature for any URL that it likes, with the body of a 307 or a 308,
;; would make the sender its signing oracle. Mastodon signs every hop, and
;; a hop to another origin is signed here only when it reads.
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

  Each signer of :signers (sign by default) is tried in turn: when the
  server answers 400 or 401, the request goes again with the next
  signature. For the fediverse, [cavage/sign sign] sends draft-cavage first
  and RFC 9421 next, as Mastodon does. A request to any URL but an http or
  https one goes unsigned, e.g. one to a relay of Nostr.

  A signature covers the URL, so each hop of a redirect needs its own.
  The request carries a :prepare-fn that signs each hop again, which
  wary-fetch calls before it sends the hop. A hop to another origin is
  signed only when it's a GET or a HEAD, so that a server can't redirect
  a signed POST to a URL of its choosing. A browser follows its own
  redirects, so there only the first hop has a signature."
  ([send key]
   (sender send key {}))
  ([send key opts]
   (let [signers (:signers opts [sign])]
     (fn [request]
       (if-not (web-request? request)
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
  "A new key map of the algorithm `alg` with the `keyid` (or in
  ClojureScript a promise of it). An HMAC key has its :secret, and any
  other its :pem and the :public-pem to publish, e.g. in an actor
  document. The secret and the private key are hidden texts.

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
