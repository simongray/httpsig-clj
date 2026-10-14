(ns dk.simongray.httpsig.redirect-test
  "The sender with wary-fetch's send!, which signs each hop of a redirect
  for its own URL, between two servers on localhost that verify each
  request they get."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dk.simongray.httpsig :as httpsig]
            [dk.simongray.httpsig.rfc9421-examples :as examples]
            [dk.simongray.wary-fetch :as http])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress]))

(def actor-key
  (get examples/jwk-keys "test-key-ecc-p256"))

(defn message-of
  "The request of the `exchange` with the server at `base`, as a message."
  [base ^HttpExchange exchange]
  {:method  (keyword (str/lower-case (.getRequestMethod exchange)))
   :url     (str base (.getRequestURI exchange))
   :headers (into {} (for [[k vs] (.getRequestHeaders exchange)] [k (vec vs)]))})

(defn answer!
  "Answer the `exchange` with the `status`, the `location` of a redirect,
  or the body ok."
  [^HttpExchange exchange status location]
  (when location
    (.add (.getResponseHeaders exchange) "Location" location))
  ;; with the request body open, Java 11 closes the connection after an
  ;; answer with no body, and the client reuses it
  (.close (.getRequestBody exchange))
  (if location
    (.sendResponseHeaders exchange status -1)
    (do (.sendResponseHeaders exchange status 2)
        (with-open [out (.getResponseBody exchange)]
          (.write out (.getBytes "ok")))))
  (.close exchange))

(deftest each-hop-signed
  (let [servers  (repeatedly 2 #(HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0))
        bases    (mapv #(str "http://127.0.0.1:" (.getPort (.getAddress ^HttpServer %))) servers)
        verified (atom [])]
    (doseq [[^HttpServer server base] (map vector servers bases)]
      (.createContext server "/"
                      (reify HttpHandler
                        (handle [_ exchange]
                          (let [result (httpsig/verify (message-of base exchange) (constantly actor-key))]
                            (swap! verified conj (or (:error result) (:label result)))
                            (if (= base (first bases))
                              (answer! exchange 302 (str (second bases) "/notes/1"))
                              (answer! exchange 200 nil))))))
      (.start server))
    (try
      (let [send (httpsig/sender http/send! actor-key)]
        (is (= 200 (:status (send {:url (str (first bases) "/notes/1")}))))
        (is (= ["sig1" "sig1"] @verified) "a signature for the URL of each hop"))
      (finally
        (doseq [^HttpServer server servers]
          (.stop server 0))))))
