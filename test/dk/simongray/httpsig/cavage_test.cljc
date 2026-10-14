(ns dk.simongray.httpsig.cavage-test
  "The tests of draft-cavage signatures: Appendix C of the twelfth draft,
  and signatures in the shapes that the servers of the fediverse send,
  with the header lists that their sources have."
  (:require #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            [clojure.string :as str]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.cavage :as cavage]
            [dk.simongray.httpsig.impl.date :as date]
            [dk.simongray.httpsig.rfc9421-examples :as examples]
            [dk.simongray.httpsig.test-support :as support]))

;; draft-cavage-http-signatures-12, Appendix C, whose key has 1024 bits
;; although the draft says 2048
(def test-key
  {:keyid      "Test"
   :alg        "rsa-v1_5-sha256"
   :public-pem "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3\n6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6\nZ4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw\noYi+1hqp1fIekaxsyQIDAQAB\n-----END PUBLIC KEY-----\n"
   :pem        "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF\nNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\nUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB\nAoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\nQWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK\nkqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\nf1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u\n412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\nmSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7\nkpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA\ngIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW\nG6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI\n7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n-----END RSA PRIVATE KEY-----\n"})

(def test-request
  {:method  :post
   :url     "https://example.com/foo?param=value&pet=dog"
   :headers {"Host"           "example.com"
             "Date"           "Sun, 05 Jan 2014 21:31:40 GMT"
             "Content-Type"   "application/json"
             "Digest"         "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
             "Content-Length" "18"}
   :body    "{\"hello\": \"world\"}"})

(def appendix-c
  "The options that verify the signatures of Appendix C, at the time of the
  request's Date, with its small key, and without the policy of Mastodon,
  which the draft's examples don't follow."
  {:now-fn           (constantly (date/parse "Sun, 05 Jan 2014 21:31:40 GMT"))
   :min-rsa-bits     1024
   :required-headers []})

;; Appendix C.1, without headers, so date alone for rsa-sha256
(def default-test
  "keyId=\"Test\",algorithm=\"rsa-sha256\",signature=\"SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM=\"")

;; Appendix C.2
(def basic-test
  "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"")

(defn with-signature
  "The `message` with the Signature field `s`."
  [message s]
  (assoc-in message [:headers "Signature"] s))

(deftest signing-string
  (is (= "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT"
         (cavage/signing-string test-request ["(request-target)" "host" "date"])))
  (is (= "(request-target): get /foo\n(created): 1402170695\nhost: example.org\ncache-control: max-age=60, must-revalidate\nx-emptyheader: \nx-example: Example header with some whitespace."
         (cavage/signing-string {:method  :get
                                 :url     "https://example.org/foo"
                                 :headers {"Host"          "example.org"
                                           "X-Example"     "Example header\n    with some whitespace."
                                           "X-EmptyHeader" ""
                                           "Cache-Control" ["max-age=60" "must-revalidate"]}}
                                ["(request-target)" "(created)" "host" "cache-control" "x-emptyheader" "x-example"]
                                {:created 1402170695} {}))
      "section 2.3"))

(deftest appendix-c-verifies
  (support/run
   #(support/then (cavage/verify (with-signature test-request default-test) (constantly test-key) appendix-c)
                  (fn [result] (is (= ["date"] (:components result)) (str (:error result)))))
   #(support/then (cavage/verify (with-signature test-request basic-test) (constantly test-key) appendix-c)
                  (fn [result] (is (= "Test" (:keyid result)) (str (:error result)))))
   #(support/then (cavage/verify (with-signature test-request basic-test) (constantly test-key)
                                 (dissoc appendix-c :min-rsa-bits))
                  (fn [result] (is (= ::httpsig/invalid-key (:error result)) "a key of 1024 bits is too small")))))

(deftest appendix-c-signs-the-same
  (support/run
   #(support/then (cavage/sign test-request test-key {:signed-headers ["(request-target)" "host" "date"]})
                  (fn [signed] (is (= basic-test (get-in signed [:headers "Signature"])))))
   #(support/then (cavage/sign test-request test-key {:signed-headers ["date"]})
                  (fn [signed]
                    (is (str/ends-with? (get-in signed [:headers "Signature"])
                                        (re-find #"signature=.*" default-test)))))))

(def actor-key
  "The RSA key of an actor, the test key of RFC 9421."
  (assoc (get examples/pem-keys "test-key-rsa")
         :keyid "https://social.example/users/ann#main-key"))

(def inbox-post
  {:method  :post
   :url     "https://blog.example/inbox"
   :headers {"Content-Type" "application/activity+json"}
   :body    "{\"type\": \"Follow\"}"})

(def object-get
  {:method  :get
   :url     "https://blog.example/notes/1?page=true"
   :headers {"Accept" "application/activity+json"}})

(defn check-shape
  "Check that a message that the server `server` sends verifies: the
  `message` signed by the `opts` of sign that give its shape."
  [server message opts]
  (support/then (cavage/sign message actor-key opts)
                (fn [signed]
                  (support/then (cavage/verify signed (constantly actor-key))
                                (fn [result]
                                  (is (= (:keyid actor-key) (:keyid result)) (str server ": " (:error result))))))))

;; The shapes of the fediverse's servers, as their sources sign: the
;; headers, the name of the algorithm and the query of (request-target)
(deftest fediverse-shapes
  (support/run
   #(check-shape "Mastodon, a GET" object-get
                 {:signed-headers ["host" "date" "(request-target)"]})
   #(check-shape "Mastodon, a delivery" inbox-post
                 {:signed-headers ["host" "date" "content-type" "digest" "(request-target)"]})
   #(check-shape "GoToSocial" inbox-post
                 {:signed-headers ["(request-target)" "host" "date" "digest"] :algorithm "hs2019"})
   #(check-shape "Pleroma and Mobilizon, with the path alone" object-get
                 {:signed-headers ["(request-target)" "date" "host"] :query? false})
   #(check-shape "Pleroma and Mobilizon, a delivery" (assoc-in inbox-post [:headers "Content-Length"] "18")
                 {:signed-headers ["(request-target)" "content-length" "date" "digest" "host"]})
   #(check-shape "Bridgy Fed, with a digest on a GET" object-get
                 {:signed-headers ["date" "host" "digest" "(request-target)"]})
   #(check-shape "Lemmy" inbox-post
                 {:signed-headers ["(request-target)" "content-type" "date" "digest" "host"] :algorithm "hs2019"})
   #(check-shape "hs2019 with (created)" object-get
                 {:signed-headers ["(request-target)" "(created)" "host"]})))

(defn error-of
  "The :error of verifying the `message` with the actor's key and the
  `opts`, in ClojureScript as a promise."
  ([message]
   (error-of message {}))
  ([message opts]
   ;; a promise ignores a keyword, which isn't a JavaScript function
   (support/then (cavage/verify message (constantly actor-key) opts) #(:error %))))

(deftest verification-errors
  (support/run
   (fn []
     (support/then (cavage/sign inbox-post actor-key)
                   (fn [signed]
                     (let [field (get-in signed [:headers "Signature"])]
                       (support/all
                        [(support/then (error-of (with-signature signed (str "Signature " field)))
                                       #(is (nil? %) "a Signature prefix"))
                         (support/then (error-of (with-signature signed (str field ",keyId=\"x\"")))
                                       #(is (= ::httpsig/malformed %) "a parameter twice"))
                         (support/then (error-of (with-signature signed (str/replace field "rsa-sha256" "hmac-sha256")))
                                       #(is (= ::httpsig/wrong-algorithm %)))
                         (support/then (error-of (assoc signed :body "{\"type\": \"Block\"}"))
                                       #(is (= ::httpsig/digest-mismatch %)))
                         (support/then (error-of signed {:now-fn (constantly (support/instant 4102444800))})
                                       #(is (= ::httpsig/expired %)))
                         (support/then (error-of (assoc-in signed [:headers "Host"] "elsewhere.example"))
                                       #(is (= ::httpsig/invalid-signature %)))
                         (support/then (error-of (update signed :headers dissoc "Signature"))
                                       #(is (= ::httpsig/unsigned %)))])))))
   #(support/then (cavage/sign inbox-post actor-key {:signed-headers ["(request-target)" "host" "date"]})
                  (fn [signed]
                    (support/then (error-of signed)
                                  (fn [e] (is (= ::httpsig/not-covered e) "Mastodon wants a digest of a POST")))))))

;; Signature fields that no server of the fediverse sends, but a stranger
;; can
(deftest hostile-signatures
  (support/run
   (fn []
     (support/then (cavage/sign object-get actor-key)
                   (fn [signed]
                     (let [field (get-in signed [:headers "Signature"])]
                       (support/all
                        [(support/then (error-of (with-signature signed (apply str (repeat 100000 "a"))))
                                       #(is (= ::httpsig/malformed %) "a run of letters, which took minutes with a regex"))
                         (support/then (error-of (with-signature signed (str/replace field "headers=\"" "headers=\"date ")))
                                       #(is (= ::httpsig/malformed %) "a header signed twice"))
                         (support/then (error-of (with-signature signed (str field ",created=10000000000000000000000000")))
                                       #(is (nil? %) "a created out of range, which it doesn't sign"))])))))))

;; A signature that can't verify fails before the key function, which may
;; fetch an actor
(deftest errors-before-the-key
  (let [calls (atom 0)
        key-fn (fn [_] (swap! calls inc) actor-key)]
    (support/run
     (fn []
       (support/then (cavage/sign inbox-post actor-key {:signed-headers ["(request-target)" "host" "date" "digest" "content-type"]})
                     (fn [signed]
                       (support/all
                        [(support/then (cavage/verify (update signed :headers dissoc "Content-Type") key-fn)
                                       (fn [result]
                                         (is (= {:error ::httpsig/missing-component :component "content-type"}
                                                (select-keys result [:error :component])))))
                         (support/then (cavage/verify (update signed :headers dissoc "Date") key-fn)
                                       (fn [result]
                                         (is (= {:error ::httpsig/missing-component :component "date"}
                                                (select-keys result [:error :component])))))
                         (support/then (cavage/verify (update signed :headers dissoc "Digest") key-fn)
                                       (fn [result]
                                         (is (= {:error ::httpsig/missing-component :component "digest"}
                                                (select-keys result [:error :component])))))]))))
     #(is (zero? @calls)))))

;; Mastodon's policy, with host for every method but POST and a digest of
;; any body
(deftest policy
  (let [error-when-signed (fn [message opts]
                            (support/then (cavage/sign message actor-key opts) error-of))]
    (support/run
     #(support/then (error-when-signed (assoc inbox-post :method :put) {:signed-headers ["(request-target)" "host" "date"]})
                    (fn [e] (is (= ::httpsig/not-covered e) "a PUT with a body needs a digest")))
     #(support/then (error-when-signed (assoc inbox-post :method :delete :body nil) {:signed-headers ["(request-target)" "date"]})
                    (fn [e] (is (= ::httpsig/not-covered e) "a DELETE needs host")))
     #(support/then (error-when-signed inbox-post {:signed-headers ["(request-target)" "date" "digest"]})
                    (fn [e] (is (nil? e) "a POST needs no host, as in Mastodon")))
     #(support/then (error-when-signed (assoc inbox-post :url "https://blog.example/inbox?x=1") {:query? false})
                    (fn [e] (is (= ::httpsig/invalid-signature e) "a POST has its query signed")))
     #(support/then (support/outcome (fn [] (cavage/sign object-get (assoc actor-key :keyid "a\",headers=\"date"))))
                    (fn [{:keys [error]}] (is (= ::httpsig/invalid-key error) "a keyId with a quote"))))))
