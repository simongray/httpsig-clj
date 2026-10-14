(ns dk.simongray.httpsig.sender-test
  "The tests of the sender, with a send of their own in place of
  wary-fetch's."
  (:require #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.cavage :as cavage]
            [dk.simongray.httpsig.rfc9421-examples :as examples]
            [dk.simongray.httpsig.test-support :as support]))

(def actor-key
  (assoc (get examples/pem-keys "test-key-rsa")
         :keyid "https://blog.example/actor#main-key"))

(defn rfc9421-only
  "A send of a server that answers 401 to a request without a signature of
  RFC 9421, and 202 with the request otherwise, and that keeps each request
  in the atom `sent`."
  [sent]
  (fn [request]
    (swap! sent conj request)
    (if (get-in request [:headers "Signature-Input"])
      {:status 202 :request request}
      {:status 401})))

(deftest double-knock
  (let [sent (atom [])
        send (httpsig/sender (rfc9421-only sent) actor-key {:signers [cavage/sign httpsig/sign]})]
    (support/run
     (fn []
       (support/then (send {:method       :post
                            :url          "https://social.example/inbox"
                            :query-params {:page 2}
                            :body         "{}"})
                     (fn [response]
                       (is (= 202 (:status response)))
                       (is (= 2 (count @sent)) "draft-cavage first, then RFC 9421")
                       (is (nil? (get-in response [:request :headers "Digest"]))
                           "the second signature has none of the first's fields")
                       (is (= "https://social.example/inbox?page=2" (get-in response [:request :url])))
                       (support/then (httpsig/verify (:request response) (constantly actor-key))
                                     #(is (= "sig1" (:label %)) (str (:error %))))))))))

(deftest hops
  (let [send (httpsig/sender (fn [request] {:status 200 :request request}) actor-key)]
    (support/run
     (fn []
       (support/then (send {:url "https://social.example/notes/1"})
                     (fn [{:keys [request]}]
                       ;; a client that follows a redirect signs the next hop
                       (support/then ((:prepare-fn request) (assoc request :url "https://other.example/notes/1"))
                                     (fn [hop]
                                       (is (= 1 (count (httpsig/signatures hop))))
                                       (support/then (httpsig/verify hop (constantly actor-key))
                                                     #(is (= "sig1" (:label %)) (str (:error %)))))))))
     #(support/then (send {:url "wss://relay.example" :filters []})
                    (fn [{:keys [request]}]
                      (is (nil? (:headers request)) "a request to a relay goes unsigned"))))))
