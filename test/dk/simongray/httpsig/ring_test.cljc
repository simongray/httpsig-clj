(ns dk.simongray.httpsig.ring-test
  "The tests of signed Ring requests."
  (:require #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            [clojure.string :as str]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.cavage :as cavage]
            [dk.simongray.httpsig.ring :as ring]
            [dk.simongray.httpsig.rfc9421-examples :as examples]
            [dk.simongray.httpsig.test-support :as support]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.whatwg-url :as url])
  #?(:clj (:import [java.io ByteArrayInputStream])))

(def actor-key
  (get examples/jwk-keys "test-key-ecc-p256"))

(def delivery
  {:method  :post
   :url     "https://example.com/inbox?x=1"
   :headers {"Content-Type" "application/activity+json"}
   :body    "{\"type\": \"Follow\"}"})

(defn ring-request
  "The Ring request that a server behind a proxy that ends TLS gets for the
  `message`, whose URL is https."
  [{:keys [method url headers body]}]
  (let [u (url/parse url)]
    {:request-method method
     :scheme         :http
     :uri            (url/pathname u)
     :query-string   (:query u)
     :headers        (into {"host" (url/host u)}
                           (for [[k v] headers] [(str/lower-case k) v]))
     :body           (when body
                       #?(:clj  (ByteArrayInputStream. (bytes/encode body))
                          :cljs (bytes/encode body)))}))

(defn body-text
  "The text of the body of the Ring `request`, which the handler can read
  again."
  [request]
  #?(:clj  (slurp (:body request))
     :cljs (bytes/decode (:body request))))

(defn handler
  "A handler that answers with the result of the signature, and the body
  that it read."
  ([request]
   {:status 200
    :body   {:signature (::httpsig/signature request)
             :body      (body-text request)}})
  ([request respond _]
   (respond (handler request))))

(def opts
  {:origin "https://example.com"})

(deftest verified-requests
  (support/run
   (fn []
     (support/then
      (httpsig/sign delivery actor-key)
      (fn [signed]
        (support/all
         [(support/then (ring/verified (ring-request signed) (constantly actor-key) opts)
                        (fn [request]
                          (is (= "sig1" (:label (::httpsig/signature request))))
                          (is (= (:body delivery) (body-text request)) "the body reads again")))
          (support/then (ring/verified (ring-request signed) (constantly actor-key))
                        (fn [request]
                          (is (= ::httpsig/invalid-signature (:error (::httpsig/signature request)))
                              "without the public origin, the URL is http")))
          (support/then (ring/verified (ring-request signed) (constantly actor-key) (assoc opts :max-bytes 5))
                        (fn [request]
                          (is (= ::httpsig/too-large (:error (::httpsig/signature request))))))]))))
   #(support/then (ring/verified (assoc (ring-request delivery) :body :unread) (constantly actor-key) opts)
                  (fn [request]
                    (is (not (contains? request ::httpsig/signature)) "unsigned")
                    (is (= :unread (:body request)) "an unsigned request keeps its body unread")))))

;; RFC 9110, section 7.2: a Host with a path in it would move the path of
;; the URL that a signature covers
(deftest forged-host
  (support/run
   (fn []
     (support/then
      (httpsig/sign (assoc delivery :url "https://example.com/users/ann/inbox") actor-key)
      (fn [signed]
        (let [request (-> (ring-request (assoc signed :url "https://example.com/inbox"))
                          (assoc :scheme :https)
                          (assoc-in [:headers "host"] "example.com/users/ann"))]
          (support/then (ring/verified request (constantly actor-key))
                        (fn [request]
                          (is (= ::httpsig/missing-component (:error (::httpsig/signature request)))
                              "a URL of no Host rather than the signed one")))))))))

(def rsa-key
  (get examples/pem-keys "test-key-rsa"))

(deftest draft-cavage
  (support/run
   (fn []
     (support/then
      (cavage/sign delivery rsa-key)
      (fn [signed]
        (support/all
         [(support/then (ring/verified (ring-request signed) (constantly rsa-key) (assoc opts :cavage? true))
                        (fn [request] (is (= "test-key-rsa" (:keyid (::httpsig/signature request))))))
          (support/then (ring/verified (ring-request signed) (constantly rsa-key) opts)
                        (fn [request] (is (not (contains? request ::httpsig/signature))
                                          "without :cavage?, a draft-cavage signature is none")))]))))))

(deftest middleware
  (let [app (ring/wrap-verify handler (constantly actor-key) (assoc opts :required? true
                                                                   :accept-signature "sig1=(\"@method\")"))]
    (support/run
     (fn []
       (support/then
        (httpsig/sign delivery actor-key)
        (fn [signed]
          (support/all
           [(support/then (app (ring-request signed))
                          (fn [response]
                            (is (= 200 (:status response)))
                            (is (= (:body delivery) (:body (:body response))))))
            (support/then (app (ring-request (assoc signed :body "{\"type\": \"Block\"}")))
                          (fn [response]
                            (is (= 401 (:status response)))
                            (is (= "The signature doesn't verify: digest-mismatch" (:body response)))))
            (support/then (app (ring-request delivery))
                          (fn [response]
                            (is (= 401 (:status response)))
                            (is (= "sig1=(\"@method\")" (get-in response [:headers "Accept-Signature"])))))
            #?(:clj (let [result (promise)]
                      (app (ring-request signed) #(deliver result %) #(deliver result %))
                      (is (= 200 (:status (deref result 10000 nil))) "the asynchronous arity")))])))))))
