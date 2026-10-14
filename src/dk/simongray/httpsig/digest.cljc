(ns dk.simongray.httpsig.digest
  "Digest Fields by RFC 9530: the Content-Digest and Repr-Digest of a body,
  and the Want- fields that ask for them.

  The library computes the digests of the two active algorithms of RFC
  9530's registry, sha-256 and sha-512. The others are deprecated, and RFC
  9530 forbids them wherever an attacker may be involved."
  (:require [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.httpsig.sfv :as sfv]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]))

;; RFC 9530, section 5
(def algorithms
  "The hash of each algorithm of RFC 9530's registry that the library
  computes, by its name in the fields."
  {"sha-256" :sha-256
   "sha-512" :sha-512})

(defn- hash-of
  "The hash of the algorithm named `algorithm-name`, or a throw when the
  library doesn't compute it."
  [algorithm-name]
  (or (get algorithms algorithm-name)
      (throw (ex-info (str "The library computes digests by sha-256 and sha-512, not " algorithm-name)
                      {:type ::unsupported-algorithm :algorithm algorithm-name}))))

;; RFC 9530, sections 2 and 3
(defn field-value
  "The value of a Content-Digest or a Repr-Digest of the `body` by the
  `algorithm-names`, sha-256 alone unless given. The body is text (as
  UTF-8), bytes or nil.

  A Content-Digest covers the content of a message, so `body` is its body.
  A Repr-Digest covers the whole representation that it selects, which
  only you know, e.g. the whole file rather than the range of it that a
  response holds.

      (field-value \"{\\\"hello\\\": \\\"world\\\"}\")
      ;; => \"sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\""
  ([body]
   (field-value body ["sha-256"]))
  ([body algorithm-names]
   (let [b (message/body-bytes body)]
     (sfv/serialize :dictionary (for [a algorithm-names]
                                  [a (hash/digest (hash-of a) b)])))))

(defn with-content-digest
  "The `message` with a Content-Digest of its body by the
  `algorithm-names`, sha-256 alone unless given."
  ([message]
   (with-content-digest message ["sha-256"]))
  ([message algorithm-names]
   (message/with-field message "Content-Digest"
                       (field-value (:body message) algorithm-names))))

(defn- check-digest
  "The `result` of a verification with the digest by `algorithm-name` that
  the field names as `value`, checked against the bytes `b`, and reduced
  when it fails."
  [b result [algorithm-name [value]]]
  (cond
    (not (bytes/bytes? value))
    (reduced {:error ::malformed})

    (bytes/same? value (hash/digest (hash-of algorithm-name) b))
    (update result :algorithms conj algorithm-name)

    :else
    (reduced {:error ::mismatch :algorithm algorithm-name})))

;; RFC 9530, section 2, and section 6.3 on its use in signatures
(defn verify
  "The outcome of checking the Content-Digest of the `message` against its
  body, as a map of the :algorithms that matched, or of an :error.

  Every digest by one of the :algorithms in `opts` (sha-256 and sha-512 by
  default) has to match, and there has to be at least one. The :error is
  one of these:

  - ::missing, for a message without a Content-Digest
  - ::malformed, for one that isn't a Dictionary of Byte Sequences
  - ::unsupported-algorithm, for one without a digest by the :algorithms
  - ::mismatch, for a digest that doesn't match the body, with its
    :algorithm"
  ([message]
   (verify message {}))
  ([message {accepted :algorithms :or {accepted (set (keys algorithms))} :as opts}]
   (let [lines (message/field-lines (:headers message) "content-digest")
         field (sfv/parse :dictionary lines)
         known (filter #(contains? accepted (first %)) field)]
     (cond
       (nil? lines) {:error ::missing}
       (nil? field) {:error ::malformed}
       (empty? known) {:error ::unsupported-algorithm}
       :else (reduce (partial check-digest (message/body-bytes (:body message)))
                     {:algorithms []}
                     known)))))

;; RFC 9530, section 4
(defn wanted
  "The names of the algorithms that the Want-Content-Digest or
  Want-Repr-Digest `s` asks for and the library computes, most wanted
  first. The field is text or field lines.

      (wanted \"sha-512=3, sha-256=10, unixsum=0\")
      ;; => [\"sha-256\" \"sha-512\"]"
  [s]
  (->> (sfv/parse :dictionary s)
       (keep (fn [[k [weight]]]
               (when (and (contains? algorithms k) (integer? weight) (<= 1 weight 10))
                 [k weight])))
       (sort-by (comp - second))
       (mapv first)))

(comment
  (field-value "{\"hello\": \"world\"}" ["sha-256" "sha-512"])
  (verify (with-content-digest {:body "{\"hello\": \"world\"}"}))
  (wanted "sha-512=3, sha-256=10, unixsum=0")
  #_.)
