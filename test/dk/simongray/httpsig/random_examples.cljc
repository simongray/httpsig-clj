(ns dk.simongray.httpsig.random-examples
  "Random requests and the components that a signature of them covers, for
  the tests that check this library against others. Each example is
  deterministic by its seed, so a failure can be made again."
  (:require [clojure.string :as str]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.random :as random]
            [clojure.test.check.rose-tree :as rose]
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.whatwg-url.params :as params]))

(def hosts
  ["example.com" "api.example.org" "example.com:8443"])

(def query-names
  ["a" "b" "page" "Pet" "q"])

(def field-names
  "The names of the fields of a request, beside Content-Digest."
  ["content-type" "accept" "x-example" "date"])

(def derived-components
  "The derived components of a request that the other libraries all derive
  from its URL. @request-target is left out, as dhensby's library advises."
  ["@method" "@target-uri" "@authority" "@scheme" "@path" "@query"])

(def text-gen
  "Text of letters and digits, with spaces between them."
  (gen/fmap #(str/join " " %)
            (gen/vector (gen/not-empty gen/string-alphanumeric) 1 3)))

(defn url-of
  "The URL of the `host`, the path `segments` and the `query` pairs, as
  whatwg-url writes it, with a space in the query as +."
  [host segments query]
  (str "https://" host "/" (str/join "/" segments)
       (when (seq query) (str "?" (params/serialize query)))))

(defn single-names
  "The names that the `query` pairs have once."
  [query]
  (->> (frequencies (map first query))
       (keep (fn [[k n]] (when (= 1 n) k)))
       sort))

(defn message-of
  "The request of the `method` to the `url` with the `fields`, pairs of a
  name and a value or values, and the `body`, with a Content-Digest when it
  has one."
  [method url fields body]
  (cond-> {:method  method
           :url     url
           :headers (into {} fields)}
    body (-> (assoc :body body) digest/with-content-digest)))

(def example-gen
  "A random example: a map of the request as a :message, the :components
  that its signature covers, in order, and its :nonce and :tag when it has
  them."
  (gen/let [method   (gen/elements [:get :post :put :delete])
            host     (gen/elements hosts)
            segments (gen/vector gen/string-alphanumeric 0 3)
            query    (gen/vector (gen/tuple (gen/elements query-names) text-gen) 0 3)
            names    (gen/vector-distinct (gen/elements field-names) {:max-elements 3})
            values   (gen/vector (gen/one-of [text-gen (gen/vector text-gen 2)]) 3)
            body     (gen/one-of [(gen/return nil) text-gen])
            nonce    (gen/one-of [(gen/return nil) (gen/not-empty gen/string-alphanumeric)])
            tag      (gen/one-of [(gen/return nil) (gen/not-empty gen/string-alphanumeric)])
            order    (gen/shuffle (concat derived-components
                                          (for [n (single-names query)]
                                            ["@query-param" {"name" n}])
                                          names
                                          (when body ["content-digest"])))
            n        (gen/choose 1 (count order))]
    {:message    (message-of method (url-of host segments query) (map vector names values) body)
     :components (vec (take n order))
     :nonce      nonce
     :tag        tag}))

(defn examples
  "The `n` examples of the seeds from 0, each of a size up to 30."
  [n]
  (for [seed (range n)]
    (rose/root (gen/call-gen example-gen (random/make-random seed) 30))))

(defn component-text
  "The `component` as the text of a component identifier without quotes
  around its name, as dhensby's library takes it, e.g. @query-param;name=\"Pet\"."
  [component]
  (if (vector? component)
    (let [[component-name params] component]
      (apply str component-name (for [[k v] params] (str ";" k "=\"" v "\""))))
    component))
