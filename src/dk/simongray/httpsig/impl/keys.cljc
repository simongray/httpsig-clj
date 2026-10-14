(ns ^:no-doc dk.simongray.httpsig.impl.keys
  "The keys of signatures: the algorithms of RFC 9421 in webcrypto-clj's
  terms, and the import of a key map's material for signing or verifying.

  A key map has a :keyid, an :alg and the key material: a :pem, a :jwk, a
  :secret or a webcrypto-clj :key. The functions that import return a map
  of the :alg and the :key that they imported (in ClojureScript a promise
  of it). They throw ::httpsig/invalid-key for material that doesn't
  import, and ::httpsig/unsupported-algorithm for an algorithm that the
  library or the platform lacks."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig :as-alias httpsig]
            [dk.simongray.httpsig.impl.async :as async]
            [dk.simongray.wary-fetch.async :as wary-async]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.pem :as pem]))

(def rsa-generation
  "The parameters of a new RSA key of 2048 bits, but for its hash."
  {:modulus-length 2048 :public-exponent (bytes/of [1 0 1])})

;; RFC 9421, sections 3.3.1 to 3.3.6
(def algorithms
  "The algorithms of RFC 9421's registry, by name, as webcrypto-clj takes
  them: the algorithm to :import a key for, to :sign and verify with, and
  to :generate a key by."
  {"rsa-pss-sha512"    {:import   {:name :rsa-pss :hash :sha-512}
                        :sign     {:name :rsa-pss :salt-length 64}
                        :generate (merge {:name :rsa-pss :hash :sha-512} rsa-generation)}
   "rsa-v1_5-sha256"   {:import   {:name :rsassa-pkcs1-v1_5 :hash :sha-256}
                        :sign     :rsassa-pkcs1-v1_5
                        :generate (merge {:name :rsassa-pkcs1-v1_5 :hash :sha-256} rsa-generation)}
   "hmac-sha256"       {:import   {:name :hmac :hash :sha-256}
                        :sign     :hmac
                        :generate {:name :hmac :hash :sha-256}}
   "ecdsa-p256-sha256" {:import   {:name :ecdsa :named-curve :p-256}
                        :sign     {:name :ecdsa :hash :sha-256}
                        :generate {:name :ecdsa :named-curve :p-256}}
   "ecdsa-p384-sha384" {:import   {:name :ecdsa :named-curve :p-384}
                        :sign     {:name :ecdsa :hash :sha-384}
                        :generate {:name :ecdsa :named-curve :p-384}}
   "ed25519"           {:import   :ed25519
                        :sign     :ed25519
                        :generate :ed25519}})

(defn invalid-key
  "The exception of a key that doesn't import, for the reason `why`."
  ([why]
   (invalid-key why nil))
  ([why cause]
   (ex-info why {:type ::httpsig/invalid-key} cause)))

(defn unsupported
  "The exception of the algorithm `alg` that the library or the platform
  lacks, for the reason `why`."
  [alg why]
  (ex-info why {:type ::httpsig/unsupported-algorithm :alg alg}))

(defn check-algorithm
  "The algorithm `alg`, or a throw when it isn't one of RFC 9421's."
  [alg]
  (if (contains? algorithms alg)
    alg
    (throw (unsupported alg (str "The algorithms of RFC 9421 are " (pr-str (sort (keys algorithms)))
                                 ", not " (pr-str alg))))))

(def curve-algorithms
  "The algorithm of ECDSA on each curve, by webcrypto-clj's name for it."
  {:p-256 "ecdsa-p256-sha256"
   :p-384 "ecdsa-p384-sha384"})

(defn kind-algorithm
  "The algorithm of a key with the :kind and :named-curve that
  webcrypto-clj's pem/key-data returns, or nil. An RSA key is
  rsa-v1_5-sha256, as Mastodon reads it, and one of RSASSA-PSS is for
  rsa-pss-sha512 alone."
  [{:keys [kind named-curve]}]
  (case kind
    :rsa     "rsa-v1_5-sha256"
    :rsa-pss "rsa-pss-sha512"
    :ec      (curve-algorithms named-curve)
    :ed25519 "ed25519"
    nil))

(defn jwk-algorithm
  "The algorithm of the JWK `jwk` by its key type, or nil."
  [{:keys [kty crv] :as jwk}]
  (case kty
    "RSA" "rsa-v1_5-sha256"
    "EC"  (case crv "P-256" "ecdsa-p256-sha256" "P-384" "ecdsa-p384-sha384" nil)
    "OKP" (when (= "Ed25519" crv) "ed25519")
    "oct" "hmac-sha256"
    nil))

(defn crypto-key-algorithm
  "The algorithm of RFC 9421 that the key `k` of webcrypto-clj is for, or
  nil."
  [k]
  (let [{:keys [name hash named-curve]} (:algorithm (webcrypto/key-info k))]
    (case name
      :rsassa-pkcs1-v1_5 (when (= :sha-256 hash) "rsa-v1_5-sha256")
      :rsa-pss           (when (= :sha-512 hash) "rsa-pss-sha512")
      :hmac              (when (= :sha-256 hash) "hmac-sha256")
      :ecdsa             (curve-algorithms named-curve)
      :ed25519           "ed25519"
      nil)))

(defn jwk-of
  "The JWK `jwk` with its members as keywords, and without the members that
  limit its use, since the library sets the usages itself."
  [jwk]
  (-> (update-keys jwk keyword)
      (dissoc :key_ops :use :ext)))

;; RFC 7518, section 6
(defn public-jwk
  "The JWK `jwk` without the members of a private key."
  [{:keys [kty] :as jwk}]
  (cond-> jwk
    (not= "oct" kty) (dissoc :d :p :q :dp :dq :qi :oth)))

;; RFC 7518, section 6
(def private-jwk-members
  "The members of a JWK that hold a private key or a secret."
  [:d :p :q :dp :dq :qi :oth :k])

;; A result can reach a log, e.g. in a Ring request that a handler prints
(defn shown
  "The key map `key` without the material of a private key or a secret, as
  the result of a verification shows it."
  [{:keys [pem jwk] :as key}]
  (cond-> (dissoc key :secret)
    (some-> pem secret/reveal (str/includes? "PRIVATE KEY"))
    (dissoc :pem)

    jwk
    (assoc :jwk (apply dissoc jwk (mapcat (juxt identity name) private-jwk-members)))))

(defn secret-bytes
  "The bytes of the shared secret `s`: bytes, or text as UTF-8, hidden
  with wary-fetch's secret/hide or not."
  [s]
  (let [s (secret/reveal s)]
    (if (string? s) (bytes/encode s) s)))

(defn pem-material
  "The key in the PEM text `s` as the :format and :data that import-key
  takes."
  [s]
  (let [{:keys [value error]} (try {:value (pem/key-data (secret/reveal s))}
                                   (catch #?(:clj Exception :cljs :default) e
                                     {:error e}))]
    (or value (throw (invalid-key "The PEM holds no key that the library reads" error)))))

(defn translated
  "The library's own exception for `e`, the exception of webcrypto-clj
  when it imports a key for the algorithm `alg`."
  [e alg]
  (if (= ::webcrypto/not-supported-error (async/error-type e))
    (unsupported alg (str "The platform lacks " alg ": " (ex-message e)))
    (invalid-key (str "The key isn't one of " alg ": " (ex-message e)) e)))

(defn imported
  "The key of the `material` for the algorithm `alg`, with the `usages`, as
  a map of the :alg and the :key, which is `extractable` (or not)."
  ([material alg usages]
   (imported material alg usages false))
  ([{:keys [format data]} alg usages extractable]
   (wary-async/then (async/attempt #(webcrypto/import-key format data (:import (get algorithms alg))
                                                          extractable usages))
                    (fn [{:keys [value error]}]
                      (if error
                        (throw (translated error alg))
                        {:alg alg :key value})))))

(defn algorithm-of
  "The algorithm of the key map `key`: its :alg, or else that of its
  `material`, the :format and :data of import-key, with the :kind that
  pem/key-data returns for a PEM key. A PEM key of RSASSA-PSS with another
  :alg throws, since RFC 9421, section 7.3.6, keeps a key to one
  algorithm."
  [{:keys [alg jwk secret] :as key} material]
  (cond
    (and alg (= :rsa-pss (:kind material)) (not= "rsa-pss-sha512" alg))
    (throw (invalid-key (str "The key is of RSASSA-PSS, so for rsa-pss-sha512 alone, not " alg)))

    alg    (check-algorithm alg)
    secret "hmac-sha256"
    jwk    (or (jwk-algorithm (jwk-of jwk))
               (throw (invalid-key "The JWK is of no algorithm of RFC 9421")))
    :else  (or (kind-algorithm material)
               (throw (invalid-key "The PEM key is of no algorithm of RFC 9421")))))

(defn material
  "The material of the key map `key` as the :format and :data that
  import-key takes, its public part when `public?`."
  [{:keys [pem public-pem jwk secret]} public?]
  (cond
    secret               {:format :raw :data (secret-bytes secret)}
    jwk                  {:format :jwk :data (cond-> (jwk-of jwk) public? public-jwk)}
    (and public? public-pem) (pem-material public-pem)
    pem                  (pem-material pem)
    :else                (throw (invalid-key "A key has its :pem, :jwk, :secret or :key"))))

(defn given-key
  "The :key of webcrypto-clj of the key map `key` as a map of its :alg and
  the :key."
  [{k :key alg :alg}]
  {:alg (or (some-> alg check-algorithm)
            (crypto-key-algorithm k)
            (throw (invalid-key "The key is for no algorithm of RFC 9421")))
   :key k})

(defn signing-key
  "The key of the key map `key` to sign with."
  [key]
  (async/promised
   #(if (:key key)
      (given-key key)
      (let [m (material key false)]
        (imported m (algorithm-of key m) [:sign])))))

(defn public-of
  "The public key of the private key `imported`, as a map of its :alg and
  its :key, from its JWK."
  [{:keys [alg key]}]
  (wary-async/then (webcrypto/export-key :jwk key)
                   #(imported {:format :jwk :data (public-jwk (jwk-of %))} alg [:verify])))

(defn verifying-key
  "The key of the key map `key` to verify with: the public key of a key
  pair, which it derives from a private key in PEM too."
  [key]
  (async/promised
   #(if (:key key)
      (given-key key)
      (let [{:keys [format] :as m} (material key true)
            alg                    (algorithm-of key m)]
        (if (= :pkcs8 format)
          (wary-async/then (imported m alg [:sign] true) public-of)
          (imported m alg [:verify]))))))

(defn modulus-bits
  "The bits of the modulus of the RSA key `k` of webcrypto-clj, or nil for
  a key of another kind."
  [k]
  (get-in (webcrypto/key-info k) [:algorithm :modulus-length]))

(defn import-error
  "The :error of a key map whose import for verifying threw `e`."
  [e]
  (if (= ::httpsig/unsupported-algorithm (async/error-type e))
    ::httpsig/unsupported-algorithm
    ::httpsig/invalid-key))

(defn policy-error
  "The :error of the imported key `verifier`, a map of its :alg and :key,
  that the :algorithms and :min-rsa-bits of `opts` refuse, or nil."
  [{:keys [alg key] :as verifier} {:keys [algorithms min-rsa-bits] :as opts}]
  (let [bits (modulus-bits key)]
    (cond
      (not (contains? algorithms alg)) ::httpsig/wrong-algorithm
      (and bits (< bits min-rsa-bits)) ::httpsig/invalid-key)))

;; PEM labels, RFC 7468, section 10 and 11
(defn generate-key
  "A new key map of the algorithm `alg` with the `keyid`: for HMAC its
  :secret, and else its :pem and :public-pem. The secret and the private
  PEM are hidden with wary-fetch's secret/hide."
  [alg keyid]
  (let [{:keys [generate]} (get algorithms (check-algorithm alg))]
    (wary-async/then
     (async/attempt #(webcrypto/generate-key generate true [:sign :verify]))
     (fn [{generated :value e :error}]
       (cond
         ;; e.g. Ed25519 below Java 15
         (= ::webcrypto/not-supported-error (async/error-type e))
         (throw (translated e alg))

         e
         (throw e)

         (= "hmac-sha256" alg)
         (wary-async/then (webcrypto/export-key :raw generated)
                          #(hash-map :keyid keyid :alg alg :secret (secret/hide %)))

         :else
         (wary-async/then
          (wary-async/all [(webcrypto/export-key :pkcs8 (:private-key generated))
                           (webcrypto/export-key :spki (:public-key generated))])
          (fn [[private public]]
            {:keyid      keyid
             :alg        alg
             :pem        (secret/hide (pem/encode "PRIVATE KEY" private))
             :public-pem (pem/encode "PUBLIC KEY" public)})))))))
