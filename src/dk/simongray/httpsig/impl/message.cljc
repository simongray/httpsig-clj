(ns ^:no-doc dk.simongray.httpsig.impl.message
  "The parts of a message that signatures and digests read and write: its
  fields by name, and its body as bytes. A message is a request or a
  response map of wary-fetch, whose header names can be in any case and
  whose values are texts, hidden texts or vectors of them."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig :as-alias httpsig]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.webcrypto.bytes :as bytes]))

(defn field-name?
  "Whether the header name `k` (a string or a keyword) names the field
  `field-name`, which is in lower case."
  [field-name k]
  (= field-name (str/lower-case (name k))))

(defn field-lines
  "The values of the field `field-name` in the `headers`, as texts in order,
  or nil when it has none. Hidden texts count as their texts."
  [headers field-name]
  (let [field-name (str/lower-case field-name)
        lines      (for [[k v] headers
                         :when (field-name? field-name k)
                         line  (if (sequential? v) v [v])]
                     (str (secret/reveal line)))]
    (when (seq lines)
      (vec lines))))

(defn with-field
  "The `message` with the field `field-name` set to the text `value`, in
  place of the field in whatever case its headers name it."
  [message field-name value]
  (let [lower (str/lower-case field-name)]
    (update message :headers
            (fn [headers]
              (-> (into {} (remove #(field-name? lower (key %))) headers)
                  (assoc field-name value))))))

(defn body-bytes
  "The bytes of the `body` of a message: text as UTF-8, bytes as they are,
  and no body as no bytes. A hidden text counts as its text."
  [body]
  (let [body (secret/reveal body)]
    (cond
      (nil? body)         (bytes/of [])
      (string? body)      (bytes/encode body)
      (bytes/bytes? body) body
      :else               (throw (ex-info "The body of a message to sign or digest is text or bytes, not a stream or a collection"
                                          {:type ::httpsig/invalid-body})))))

(defn has-body?
  "Whether the `message` has a body of at least one byte."
  [message]
  (pos? (bytes/length (body-bytes (:body message)))))
