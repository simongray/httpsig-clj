(ns dk.simongray.httpsig.node-test
  "The tests in Node alone: checks of this library against dhensby's
  http-message-signatures (https://github.com/dhensby/node-http-message-signatures),
  which signs with node:crypto. Each verifies what the other signs, for
  random requests and components."
  (:require [cljs.test :refer-macros [deftest is]]
            ["http-message-signatures" :as hms]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.httpsig.random-examples :as random]
            [dk.simongray.httpsig.test-support :as support]
            [dk.simongray.wary-fetch.secret :as secret]))

(def examples-per-algorithm
  25)

(defn private-key-of
  "The private key of the key map `k` as node:crypto takes it: PEM, or the
  bytes of a secret."
  [k]
  (secret/reveal (or (:secret k) (:pem k))))

(defn public-key-of
  "The public key of the key map `k` as node:crypto takes it."
  [k]
  (secret/reveal (or (:secret k) (:public-pem k))))

(defn js-message
  "The `message` as dhensby's library takes it."
  [{:keys [method url headers]}]
  (clj->js {:method  (.toUpperCase (name method))
            :url     url
            :headers (into {} (for [[k v] headers] [k (if (string? v) v (vec v))]))}))

(defn their-verify
  "A promise of nil when dhensby's library verifies the signature sig1 of
  the `message` with the key map `k` of the algorithm `alg`, or else of its
  complaint."
  [message k alg]
  (let [key-lookup (fn [_]
                     (js/Promise.resolve #js {:id     "k"
                                              :algs   #js [alg]
                                              :verify (hms/createVerifier (public-key-of k) alg)}))]
    (-> (.verifyMessage (.-httpbis hms) #js {:keyLookup key-lookup} (js-message message))
        (.then #(when-not (true? %) (str "verified: " %)))
        (.catch #(str "threw: " (.-message %))))))

(defn their-sign
  "A promise of the `message` signed by dhensby's library with the key map
  `k` of the algorithm `alg`, covering the `components`, with the `nonce`
  and the `tag`, as sig1."
  [message k alg {:keys [components nonce tag]}]
  (let [params (cond-> ["created" "keyid" "alg"] nonce (conj "nonce") tag (conj "tag"))
        config (clj->js {:key         (hms/createSigner (private-key-of k) alg "k")
                         :name        "sig1"
                         :fields      (mapv random/component-text components)
                         :params      params
                         :paramValues (cond-> {:created (js/Date.)}
                                        nonce (assoc :nonce nonce)
                                        tag   (assoc :tag tag))})]
    (.then (.signMessage (.-httpbis hms) config (js-message message))
           (fn [^js signed]
             (let [headers (js->clj (.-headers signed))]
               (update message :headers assoc
                       "Signature-Input" (get headers "Signature-Input")
                       "Signature" (get headers "Signature")))))))

(defn keys-by-algorithm
  "A promise of a new key map for each algorithm."
  []
  (support/then (support/all (for [alg (sort httpsig/algorithms)]
                               (httpsig/generate-key alg "k")))
                #(zipmap (sort httpsig/algorithms) %)))

(defn in-turn
  "A promise of calling `f` on each of `xs` in turn, each of which gives a
  promise."
  [f xs]
  (reduce (fn [p x] (.then p (fn [_] (f x)))) (js/Promise.resolve nil) xs))

(deftest tampering
  (let [message (digest/with-content-digest {:method :post :url "https://example.com/inbox" :body "hi"})
        example {:components ["@method" "@target-uri" "content-digest"]}
        alg     "ecdsa-p256-sha256"]
    (support/run
     (fn []
       (support/then
        (httpsig/generate-key alg "k")
        (fn [k]
          (support/then
           (support/all [(httpsig/sign message k example) (their-sign message k alg example)])
           (fn [[ours theirs]]
             (support/all
              [(support/then (their-verify ours k alg) #(is (nil? %)))
               (support/then (their-verify (assoc ours :method :put) k alg)
                             #(is (some? %) "dhensby's library refuses a signature of another method"))
               (support/then (httpsig/verify (assoc theirs :method :put) (constantly k) {:required-components []})
                             #(is (= ::httpsig/invalid-signature (:error %))))])))))))))

(deftest they-verify-ours
  (support/run
   #(support/then
     (keys-by-algorithm)
     (fn [keys]
       (in-turn (fn [[[alg k] {:keys [message components nonce tag]}]]
                  (support/then (httpsig/sign message k {:components components :nonce nonce :tag tag})
                                (fn [signed]
                                  (support/then (their-verify signed k alg)
                                                (fn [complaint]
                                                  (is (nil? complaint)
                                                      (str alg ": " complaint " " (pr-str components))))))))
                (for [entry keys
                      example (random/examples examples-per-algorithm)]
                  [entry example]))))))

(deftest ours-verifies-theirs
  (support/run
   #(support/then
     (keys-by-algorithm)
     (fn [keys]
       (in-turn (fn [[[alg k] {:keys [message components] :as example}]]
                  (support/then (their-sign message k alg example)
                                (fn [signed]
                                  (support/then (httpsig/verify signed (constantly k) {:required-components []})
                                                (fn [result]
                                                  (is (= "sig1" (:label result))
                                                      (str alg ": " (:error result) " " (pr-str components))))))))
                (for [entry keys
                      example (random/examples examples-per-algorithm)]
                  [entry example]))))))
