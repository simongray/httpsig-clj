(ns dk.simongray.httpsig-test
  "The tests of HTTP Message Signatures, with the examples of RFC 9421."
  (:require #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            [clojure.string :as str]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.impl.date :as date]
            [dk.simongray.httpsig.rfc9421-examples :as examples]
            [dk.simongray.httpsig.test-support :as support]))

(defn signature-of
  "The signature labelled `label` of the `message`, as signatures gives
  it."
  [message label]
  (some #(when (= label (:label %)) %) (httpsig/signatures message)))

(defn at
  "A function of the time `seconds` after the epoch, for :now-fn."
  [seconds]
  (constantly (date/instant seconds)))

(defn key-fn
  "The key function of the `keys` by their keyids."
  [keys]
  (fn [{:keys [keyid]}]
    (get keys keyid)))

;; RFC 9421, the bases of the examples of Appendix B and sections 2.4 and
;; 4.3
(deftest signature-bases
  (doseq [{:keys [name message label base request]} examples/examples
          :when base]
    (let [{:keys [components params]} (signature-of message label)]
      (is (= base (httpsig/signature-base message components params {:request request}))
          name))))

(defn check-example
  "Check that the signature of the `example` verifies with its key of the
  `keys`, or that it can't on a JVM without Ed25519."
  [{:keys [name message label created request ed25519?]} keys]
  (support/then (httpsig/verify message (key-fn keys)
                                {:label               label
                                 :request             request
                                 :required-components []
                                 :now-fn              (at created)})
                (fn [result]
                  (if (and ed25519? (not support/ed25519?))
                    (is (= ::httpsig/unsupported-algorithm (:error result)) name)
                    (is (= label (:label result)) (str name ": " (:error result)))))))

(deftest examples-verify
  (support/run
   #(support/all (for [example examples/examples]
                   (check-example example examples/pem-keys)))
   #(support/all (for [example examples/examples]
                   (check-example example examples/jwk-keys)))))

(defn check-resigned
  "Check that signing the :unsigned message of the `example` again gives the
  RFC's signature, by an algorithm that always signs the same."
  [{:keys [name message unsigned label created ed25519?]}]
  (let [{:keys [components params]} (signature-of message label)
        key                         (get examples/pem-keys (:keyid params))]
    (support/then (support/outcome #(httpsig/sign unsigned key
                                                  {:components components
                                                   :label      label
                                                   :created    (date/instant created)
                                                   :expires    (:expires params)
                                                   :alg?       (contains? params :alg)}))
                  (fn [{signed :value error :error}]
                    (if (and ed25519? (not support/ed25519?))
                      (is (= ::httpsig/unsupported-algorithm error) name)
                      (is (= (select-keys (:headers message) ["Signature-Input" "Signature"])
                             (select-keys (:headers signed) ["Signature-Input" "Signature"]))
                          name))))))

(deftest deterministic-signatures
  (support/run
   #(support/all (for [example examples/examples
                       :when   (:unsigned example)]
                   (check-resigned example)))))

(defn check-transformation
  "Check whether the `message`, a transformation of the signed message of
  Appendix B.4, still verifies, as `valid?` says it does."
  [why valid? message]
  (support/then (httpsig/verify message (key-fn examples/jwk-keys)
                                {:required-components [] :now-fn (at 1618884473)})
                (fn [result]
                  (cond
                    (not support/ed25519?) (is (= ::httpsig/unsupported-algorithm (:error result)))
                    valid?                 (is (nil? (:error result)) why)
                    :else                  (is (= ::httpsig/invalid-signature (:error result)) why)))))

;; RFC 9421, Appendix B.4
(deftest transformations
  (let [signed (:message (some #(when (= "B.4" (:name %)) %) examples/examples))]
    (support/run
     #(check-transformation "an added field and query parameter" true
                            (-> signed
                                (assoc :url "https://example.org/demo?name1=Value1&Name2=value2&param=added")
                                (assoc-in [:headers "Accept-Language"] "en-US,en;q=0.5")))
     #(check-transformation "no Date, a Referer, and one line of Accept" true
                            (-> signed
                                (update :headers dissoc "Date")
                                (assoc-in [:headers "Referer"] "https://developer.example.org/demo")
                                (assoc-in [:headers "Accept"] "application/json, */*")))
     #(check-transformation "fields in another order" true
                            (update signed :headers (partial into (sorted-map))))
     #(check-transformation "another method and authority" false
                            (-> signed
                                (assoc :method :post :url "https://example.com/demo?name1=Value1&Name2=value2")
                                (assoc-in [:headers "Host"] "example.com")))
     #(check-transformation "the lines of Accept in another order" false
                            (assoc-in signed [:headers "Accept"] ["*/*" "application/json"])))))

(defn error-of
  "The :error of verifying the `message` with the `opts`, by the keys of
  Appendix B.1, in ClojureScript as a promise."
  [message opts]
  ;; a promise ignores a keyword, which isn't a JavaScript function
  (support/then (httpsig/verify message (key-fn examples/jwk-keys) opts) #(:error %)))

(deftest verification-errors
  (let [b22 (:message (nth examples/examples 1))
        b25 (:message (nth examples/examples 4))
        now (at 1618884473)]
    (support/run
     #(support/then (error-of b25 {:now-fn now})
                    (fn [e] (is (= ::httpsig/not-covered e) "the default policy wants @method")))
     #(support/then (error-of b22 {:now-fn (at (+ 1618884473 3601)) :required-components []})
                    (fn [e] (is (= ::httpsig/expired e))))
     #(support/then (error-of b22 {:now-fn (at (- 1618884473 301)) :required-components []})
                    (fn [e] (is (= ::httpsig/not-yet-valid e))))
     #(support/then (error-of (assoc b22 :body "{\"hello\": \"there\"}") {:now-fn now :required-components []})
                    (fn [e] (is (= ::httpsig/digest-mismatch e))))
     #(support/then (error-of b25 {:now-fn now :required-components [] :label "sig-b99"})
                    (fn [e] (is (= ::httpsig/unsigned e))))
     #(support/then (error-of b25 {:now-fn now :required-components ["@method"]})
                    (fn [e] (is (= ::httpsig/not-covered e))))
     #(support/then (error-of examples/test-request {})
                    (fn [e] (is (= ::httpsig/unsigned e))))
     #(support/then (error-of (assoc-in b25 [:headers "Signature-Input"] "sig-b25=(") {})
                    (fn [e] (is (= ::httpsig/malformed e))))
     #(support/then (error-of (assoc-in b25 [:headers "Date"] "Wed, 21 Apr 2021 02:07:55 GMT")
                              {:now-fn now :required-components []})
                    (fn [e] (is (= ::httpsig/invalid-signature e))))
     #(support/then (httpsig/verify b25 (constantly nil) {:now-fn now :required-components []})
                    (fn [result] (is (= ::httpsig/unknown-key (:error result))))))))

(deftest algorithm-checks
  (let [b25 (:message (nth examples/examples 4))
        now (at 1618884473)
        rsa (get examples/jwk-keys "test-key-rsa")]
    (support/run
     ;; RFC 9421, section 7.3.6: the key decides the algorithm
     #(support/then (httpsig/verify (assoc-in b25 [:headers "Signature-Input"]
                                              "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\";alg=\"ed25519\"")
                                    (key-fn examples/jwk-keys)
                                    {:now-fn now :required-components []})
                    (fn [result] (is (= ::httpsig/wrong-algorithm (:error result)))))
     #(support/then (httpsig/verify b25 (key-fn examples/jwk-keys)
                                    {:now-fn now :required-components [] :algorithms #{"ed25519"}})
                    (fn [result] (is (= ::httpsig/wrong-algorithm (:error result)))))
     #(support/then (httpsig/verify b25 (constantly rsa) {:now-fn now :required-components []})
                    (fn [result] (is (= ::httpsig/invalid-signature (:error result))))))))

(defn check-round-trip
  "Check that a message signed with a new key of the algorithm `alg`
  verifies with it, and with its :public-pem alone."
  [alg]
  (if (and (= "ed25519" alg) (not support/ed25519?))
    (support/then (support/outcome #(httpsig/generate-key alg "k"))
                  (fn [{:keys [error]}] (is (= ::httpsig/unsupported-algorithm error))))
    (support/then
     (httpsig/generate-key alg "k")
     (fn [k]
       (support/then
        (httpsig/sign {:method :post :url "https://example.com/inbox" :body "{}"} k)
        (fn [signed]
          (support/then
           (support/all [(httpsig/verify signed (constantly k))
                         (httpsig/verify signed (constantly (dissoc k :pem :alg)))])
           (fn [[result public-result]]
             (is (= alg (:alg result)) alg)
             ;; an RSA key without an :alg is rsa-v1_5-sha256, so the alg
             ;; of an RSA-PSS signature disagrees with it
             (if (= "rsa-pss-sha512" alg)
               (is (= ::httpsig/wrong-algorithm (:error public-result)) alg)
               (is (= alg (:alg public-result)) (str alg ", by its public key alone")))))))))))

(deftest round-trips
  (support/run
   #(support/all (map check-round-trip (sort httpsig/algorithms)))))

(deftest signing
  (support/run
   (fn []
     (support/then (support/outcome #(httpsig/sign examples/test-request (get examples/jwk-keys "test-key-ecc-p256")
                                                   {:components ["x-missing"]}))
                   (fn [{:keys [error]}] (is (= ::httpsig/missing-component error)))))
   #(support/then (httpsig/sign {:method :get :url "HTTPS://Example.COM:443/a b"}
                                (get examples/jwk-keys "test-shared-secret"))
                  (fn [signed]
                    (is (= "https://example.com/a%20b" (:url signed)) "the URL on the wire")
                    (is (nil? (get-in signed [:headers "Content-Digest"])) "no digest without a body")))
   #(support/then (httpsig/sign {:status 200 :body "ok"} (get examples/jwk-keys "test-shared-secret"))
                  (fn [signed]
                    (is (= "sha-256=:Jok2eyBcFs4y7UIAlCuLix4mLfxw2byfvHfElpmk8d8=:" (get-in signed [:headers "Content-Digest"])))
                    (is (= ["@status" "content-digest"] (:components (first (httpsig/signatures signed)))))))))

(deftest components
  (is (= "example.com" (httpsig/component {:url "https://Example.com:443/a?b"} "@authority")))
  (is (= "?" (httpsig/component {:url "https://example.com/a"} "@query")))
  (is (= "/a?b" (httpsig/component {:url "https://example.com/a?b"} "@request-target")))
  (is (= "a=1, b=2;x=1;y=2, c=(a b c)"
         (httpsig/component {:headers {"Example-Dict" "  a=1,    b=2;x=1;y=2,   c=(a   b   c)"}}
                            ["example-dict" {"sf" true}]
                            {:field-types {"example-dict" :dictionary}}))
      "RFC 9421, section 2.1.1")
  (is (= "(a b c)" (httpsig/component {:headers {"Example-Dict" "a=1, b=2;x=1;y=2, c=(a   b    c), d"}}
                                      ["example-dict" {"key" "c"}]))
      "RFC 9421, section 2.1.2")
  (is (= ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"
         (httpsig/component {:headers {"Example-Header" ["value, with, lots" "of, commas"]}}
                            ["example-header" {"bs" true}]))
      "RFC 9421, section 2.1.3")
  (is (= "Obsolete line folding." (httpsig/component {:headers {"X-Obs-Fold-Header" "Obsolete\n    line folding."}}
                                                     "x-obs-fold-header"))
      "RFC 9421, section 2.1")
  (is (= "this%20is%20a%20big%0Amultiline%20value"
         (httpsig/component {:url "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace"}
                            ["@query-param" {"name" "var"}]))
      "RFC 9421, section 2.2.8"))

(deftest accept-signature
  ;; RFC 9421, section 5.1
  (is (= "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"cache-control\");keyid=\"test-key-rsa-pss\";created;tag=\"app-123\""
         (httpsig/accept-signature {"sig1" {:components ["@method" "@target-uri" "@authority" "content-digest" "cache-control"]
                                            :params     {:keyid "test-key-rsa-pss" :created true :tag "app-123"}}}))))

;; Fields from strangers: each of these took minutes with a regex that
;; backtracked through the spaces, or with a field parsed again for each
;; component that names it
(deftest hostile-input
  (let [spaces  (apply str (repeat 100000 " "))
        members 2000]
    (is (= (str "a" spaces "b") (httpsig/component {:headers {"X" (str " a" spaces "b\t")}} "x")))
    (is (= "a b" (httpsig/component {:headers {"X" (str "a" spaces "\r\n" spaces "b")}} "x"))
        "an obsolete line folding with spaces around it")
    (support/run
     #(support/then
       (error-of {:method  :get
                  :url     "https://example.com/"
                  :headers {"X"               (str/join ", " (for [i (range members)] (str "m" i "=" i)))
                            "Signature-Input" (str "sig1=(\"@method\" \"@target-uri\" "
                                                   (str/join " " (for [i (range members)] (str "\"x\";key=\"m" i "\"")))
                                                   ");created=1618884473;keyid=\"test-key-ecc-p256\"")
                            "Signature"       "sig1=:AAAA:"}}
                 {:now-fn (at 1618884473)})
       (fn [e] (is (= ::httpsig/invalid-signature e) "a Dictionary named by each of its members"))))))

;; A signature of the path alone would leave the query to anyone who
;; changes it
(deftest url-policy
  (let [k       (get examples/jwk-keys "test-shared-secret")
        request {:method :get :url "https://bank.example/transfer?to=alice&amount=1"}
        check   (fn [components error]
                  (support/then (httpsig/sign request k {:components components})
                                (fn [signed]
                                  (support/then (httpsig/verify signed (constantly k))
                                                #(is (= error (:error %)) (pr-str components))))))]
    (support/run
     #(check ["@method" "@authority" "@path"] ::httpsig/not-covered)
     #(check ["@method" "@authority" "@path" "@query"] nil)
     #(check ["@method" "@authority" "@request-target"] nil)
     #(check ["@method" "@target-uri"] nil))))

(deftest error-components
  (let [k        (get examples/jwk-keys "test-shared-secret")
        delivery {:method :post :url "https://example.com/inbox" :headers {"Content-Type" "text/plain"} :body "hi"}
        error    (fn [message]
                   (support/then (httpsig/verify message (constantly k)) #(select-keys % [:error :component])))]
    (support/run
     (fn []
       (support/then (httpsig/sign delivery k {:components ["@method" "@target-uri" ["content-type" {:bs true}] "content-digest"]})
                     (fn [signed]
                       (support/all
                        [(support/then (error (update signed :headers dissoc "Content-Type"))
                                       #(is (= {:error ::httpsig/missing-component :component ["content-type" {"bs" true}]} %)
                                            "the component as signatures gives it"))
                         (support/then (error (update signed :headers dissoc "Content-Digest"))
                                       #(is (= {:error ::httpsig/missing-component :component "content-digest"} %)))]))))
     #(support/then (support/outcome (fn [] (httpsig/sign delivery k {:nonce "a\nb"})))
                    (fn [{:keys [error]}] (is (= :dk.simongray.httpsig.sfv/invalid error)))))))

;; RFC 9421, section 7.3.3: a response that covers nothing of its request
;; can stand as the answer to any other
(deftest responses-to-requests
  (let [k        (get examples/jwk-keys "test-shared-secret")
        request  {:method :get :url "https://example.com/balance"}
        response {:status 200 :body "{\"balance\": 100}"}
        bound    ["@status" ["@method" {"req" true}] ["@target-uri" {"req" true}] "content-digest"]]
    (support/run
     (fn []
       (support/then
        (httpsig/sign response k {:request request})
        (fn [signed]
          (is (= bound (:components (first (httpsig/signatures signed)))))
          (support/all
           [(support/then (httpsig/verify signed (constantly k) {:request request})
                          #(is (= "sig1" (:label %)) (str (:error %))))
            (support/then (httpsig/verify signed (constantly k)
                                          {:request (assoc request :url "https://example.com/other")})
                          #(is (= ::httpsig/invalid-signature (:error %)) "the answer to another request"))]))))
     (fn []
       (support/then
        (httpsig/sign response k)
        (fn [signed]
          (support/all
           [(support/then (httpsig/verify signed (constantly k))
                          #(is (= "sig1" (:label %)) "without a request to tie it to"))
            (support/then (httpsig/verify signed (constantly k) {:request request})
                          #(is (= {:error ::httpsig/not-covered :component ["@method" {"req" true}]}
                                  (select-keys % [:error :component]))))])))))))

;; RFC 9421, section 7.3.6, and RFC 4055, section 1.2: the private key of
;; test-key-rsa-pss is one of RSASSA-PSS, for RSA-PSS alone
(deftest rsa-pss-keys
  (let [k       {:keyid "test-key-rsa-pss" :pem examples/rsa-pss-private-pem}
        request {:method :get :url "https://example.com/"}]
    (support/run
     #(support/then (httpsig/sign request k)
                    (fn [signed]
                      (is (= "rsa-pss-sha512" (get-in (first (httpsig/signatures signed)) [:params :alg]))
                          "the kind of key decides without an :alg")
                      (support/then (httpsig/verify signed (constantly k))
                                    (fn [result] (is (= "rsa-pss-sha512" (:alg result)) (str (:error result)))))))
     #(support/then (support/outcome (fn [] (httpsig/sign request (assoc k :alg "rsa-v1_5-sha256"))))
                    (fn [{:keys [error]}] (is (= ::httpsig/invalid-key error) "another :alg"))))))

(deftest results-show-no-private-keys
  (let [request {:method :get :url "https://example.com/"}]
    (support/run
     #(support/all
       (for [k [(get examples/jwk-keys "test-shared-secret")
                (get examples/jwk-keys "test-key-ecc-p256")
                (get examples/pem-keys "test-key-ecc-p256")]]
         (support/then (httpsig/sign request k)
                       (fn [signed]
                         (support/then (httpsig/verify signed (constantly k))
                                       (fn [{:keys [key]}]
                                         (is (= (:keyid k) (:keyid key)))
                                         (is (nil? (:secret key)))
                                         (is (nil? (:pem key)))
                                         (is (nil? (get-in key [:jwk :d]))))))))))))
