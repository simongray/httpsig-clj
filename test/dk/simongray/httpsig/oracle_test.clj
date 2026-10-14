(ns dk.simongray.httpsig.oracle-test
  "Checks of this library against Visma's library of RFC 9421 on the JVM
  (https://github.com/Visma-AutoPay/http-signatures): each verifies what
  the other signs, for random requests and components."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.httpsig.random-examples :as random]
            [dk.simongray.httpsig.test-support :as support]
            [dk.simongray.wary-fetch.secret :as secret])
  (:import [net.visma.autopay.http.signature CheckedFunction PublicKeyInfo SignatureAlgorithm
            SignatureComponents SignatureContext SignatureException SignatureParameters
            SignatureSpec VerificationSpec]))

(def visma-algorithms
  {"rsa-pss-sha512"    SignatureAlgorithm/RSA_PSS_SHA_512
   "rsa-v1_5-sha256"   SignatureAlgorithm/RSA_SHA_256
   "hmac-sha256"       SignatureAlgorithm/HMAC_SHA_256
   "ecdsa-p256-sha256" SignatureAlgorithm/ECDSA_P256_SHA_256
   "ecdsa-p384-sha384" SignatureAlgorithm/ECDSA_P384_SHA_384
   "ed25519"           SignatureAlgorithm/ED_25519})

(def examples-per-algorithm
  25)

(defn base64-of-pem
  "The base64 of the DER in the PEM text `pem`, which Visma's library takes
  as a key."
  [pem]
  (-> (secret/reveal pem)
      (str/replace #"-----[^-]+-----" "")
      (str/replace #"\s" "")))

(defn private-key-of
  "The private key of the key map `k` as Visma's library takes it."
  [k]
  (if-let [s (:secret k)]
    (secret/reveal s)
    (base64-of-pem (:pem k))))

(defn public-key-of
  "The public key of the key map `k` as Visma's library takes it."
  [k]
  (if-let [s (:secret k)]
    (secret/reveal s)
    (base64-of-pem (:public-pem k))))

(defn components-of
  "The covered `components` as Visma's library takes them."
  ^SignatureComponents [components]
  (.build ^net.visma.autopay.http.signature.SignatureComponents$Builder
          (reduce (fn [b c]
                    (case c
                      "@method"     (.method b)
                      "@target-uri" (.targetUri b)
                      "@authority"  (.authority b)
                      "@scheme"     (.scheme b)
                      "@path"       (.path b)
                      "@query"      (.query b)
                      (if (vector? c)
                        (.queryParam b ^String (get-in c [1 "name"]))
                        (.header b ^String c))))
                  (SignatureComponents/builder)
                  components)))

(defn context-of
  "The `message` as the context of Visma's library."
  ^SignatureContext [{:keys [method url headers]}]
  (-> (SignatureContext/builder)
      (.method (str/upper-case (name method)))
      (.targetUri ^String url)
      (.headers ^java.util.Map (into {} (for [[k v] headers] [k (if (string? v) [v] v)])))
      .build))

(defn visma-verify
  "Nil when Visma's library verifies the signature sig1 of the `message`
  with the key map `k` of the algorithm `alg`, or else its complaint."
  [message k alg]
  (let [getter (reify CheckedFunction
                 (apply [_ _]
                   (-> (PublicKeyInfo/builder)
                       (.algorithm (visma-algorithms alg))
                       (.publicKey (public-key-of k))
                       .build)))]
    (try
      (.verify (-> (VerificationSpec/builder)
                   (.signatureLabel "sig1")
                   (.context (context-of message))
                   (.publicKeyGetter getter)
                   (.maximumAge (int 3600))
                   .build))
      nil
      (catch SignatureException e
        (str (ex-message e) ": " (some-> (ex-cause e) ex-message))))))

(defn visma-sign
  "The `message` signed by Visma's library with the key map `k` of the
  algorithm `alg`, covering the `components`, with the `nonce` and the
  `tag`, as sig1."
  [message k alg {:keys [components nonce tag]}]
  (let [params (cond-> (-> (SignatureParameters/builder)
                           (.created (long (quot (System/currentTimeMillis) 1000)))
                           (.keyId "k")
                           (.visibleAlgorithm (visma-algorithms alg)))
                 nonce (.nonce nonce)
                 tag   (.tag tag))
        result (.sign (-> (SignatureSpec/builder)
                          (.signatureLabel "sig1")
                          ;; text for a key pair, and bytes for a secret
                          (.privateKey (private-key-of k))
                          (.context (context-of message))
                          (.parameters (.build params))
                          (.components (components-of components))
                          .build))]
    (update message :headers assoc
            "Signature-Input" (.getSignatureInput result)
            "Signature" (.getSignature result))))

(defn keys-by-algorithm
  "A new key map for each algorithm that the platform has."
  []
  (into {} (for [alg (sort httpsig/algorithms)
                 :when (or support/ed25519? (not= "ed25519" alg))]
             [alg (httpsig/generate-key alg "k")])))

(deftest visma-verifies-ours
  (doseq [[alg k] (keys-by-algorithm)]
    (testing alg
      (doseq [{:keys [message components nonce tag]} (random/examples examples-per-algorithm)]
        (let [signed (httpsig/sign message k {:components components :nonce nonce :tag tag})]
          (is (nil? (visma-verify signed k alg))
              (pr-str {:components components :message signed})))))))

(deftest tampering
  (let [k       (httpsig/generate-key "ecdsa-p256-sha256" "k")
        message (digest/with-content-digest {:method :post :url "https://example.com/inbox" :body "hi"})
        example {:components ["@method" "@target-uri" "content-digest"]}
        ours    (httpsig/sign message k example)
        theirs  (visma-sign message k "ecdsa-p256-sha256" example)]
    (is (nil? (visma-verify ours k "ecdsa-p256-sha256")))
    (is (some? (visma-verify (assoc ours :method :put) k "ecdsa-p256-sha256"))
        "Visma's library refuses a signature of another method")
    (is (= ::httpsig/invalid-signature
           (:error (httpsig/verify (assoc theirs :method :put) (constantly k) {:required-components []}))))))

(deftest ours-verifies-visma
  (doseq [[alg k] (keys-by-algorithm)]
    (testing alg
      (doseq [{:keys [message components] :as example} (random/examples examples-per-algorithm)]
        (let [signed (visma-sign message k alg example)
              result (httpsig/verify signed (constantly k) {:required-components []})]
          (is (= "sig1" (:label result))
              (pr-str {:error (:error result) :components components :message signed})))))))
