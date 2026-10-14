(ns dk.simongray.httpsig.sfv-test
  "The tests of structured fields: the JSON suite of the HTTP working group
  (https://github.com/httpwg/structured-field-tests), which dev/fetch.sh
  downloads, and a few of the library's own."
  (:require #?(:clj  [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.data.json :as json])
            [clojure.string :as str]
            #?(:clj [clojure.walk :as walk])
            [dk.simongray.httpsig.impl.date :as date]
            [dk.simongray.httpsig.sfv :as sfv]
            [dk.simongray.httpsig.test-support :as support]
            [dk.simongray.webcrypto.bytes :as bytes]))

(def parse-files
  "The files of the suite whose tests parse a field."
  ["binary" "boolean" "date" "dictionary" "display-string" "examples" "item"
   "key-generated" "large-generated" "list" "listlist" "number-generated"
   "number" "param-dict" "param-list" "param-listlist" "string-generated"
   "string" "token-generated" "token"])

(def serialisation-files
  "The files of the suite whose tests serialize data."
  ["key-generated" "number" "string-generated" "token-generated"])

(defn decimal-tag
  "The number `x` tagged as a Decimal, as the suite tags its other types."
  [x]
  {"__type" "decimal" "value" x})

(defn read-suite
  "The tests in the text `s` of a file of the suite, with string keys, and
  each number that the JSON writes with a point or an exponent tagged as a
  Decimal, which JavaScript would otherwise read as an integer."
  [s]
  #?(:clj  (walk/postwalk #(if (double? %) (decimal-tag %) %) (json/read-str s))
     :cljs (js->clj (js/JSON.parse s (fn [_ v context]
                                       (if (and (number? v) context
                                                (re-find #"[.eE]" (.-source context)))
                                         (clj->js (decimal-tag v))
                                         v))))))

(defn suite
  "The tests of the file `file` of the suite, or nil without the file."
  [file]
  (some-> (support/text (str "structured-field-tests/" file ".json")) read-suite))

(def base32-digits
  "The digits of base32 (RFC 4648, section 6), in the order of their
  values."
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defn base32-bytes
  "The bytes of the base32 text `s`, as the suite writes a Byte Sequence."
  [s]
  (let [bits (mapcat (fn [c]
                       (let [v (str/index-of base32-digits c)]
                         (map #(bit-and 1 (bit-shift-right v %)) (range 4 -1 -1))))
                     (str/replace s "=" ""))]
    (bytes/of (for [byte-bits (partition 8 bits)]
                (reduce #(+ (* 2 %1) %2) 0 byte-bits)))))

(defn expected-value
  "The data of the `x` that the suite expects, in the library's terms: a
  Token as a symbol, a Byte Sequence as bytes, a Date as an inst, and a
  Decimal and a Display String as records."
  [x]
  (if-let [kind (and (map? x) (get x "__type"))]
    (let [v (get x "value")]
      (case kind
        "decimal"       (sfv/decimal v)
        "token"         (symbol v)
        "binary"        (base32-bytes v)
        "date"          (date/instant v)
        "displaystring" (sfv/display-string v)))
    (cond->> x
      (sequential? x) (mapv expected-value))))

;; ClojureScript's clojure.walk turns records into seqs, so this walks the
;; vectors alone
(defn comparable
  "The parsed field `x` with each Byte Sequence as numbers, so that two of
  them compare by value."
  [x]
  (cond
    (bytes/bytes? x) [:bytes (support/byte-values x)]
    (vector? x)      (mapv comparable x)
    :else            x))

(defn type-of
  "The type of field that the `test` names, as a keyword."
  [test]
  (keyword (get test "header_type")))

(defn canonical
  "The text that the `test` expects of a serialization."
  [test]
  (str/join ", " (or (get test "canonical") (get test "raw"))))

(defn check-parse
  "Check that the field of the `test` parses as the suite expects, and that
  it serializes again to the canonical text."
  [test]
  (let [parsed (sfv/parse (type-of test) (get test "raw"))
        name   (get test "name")]
    (cond
      (get test "must_fail")
      (is (nil? parsed) name)

      (and (get test "can_fail") (nil? parsed))
      nil

      :else
      (do (is (= (comparable (expected-value (get test "expected")))
                 (comparable parsed))
              name)
          (when parsed
            (is (= (canonical test) (sfv/serialize (type-of test) parsed))
                (str name ", serialized")))))))

(defn check-serialize
  "Check that the data of the `test` serializes to the canonical text, or
  that it doesn't serialize when it mustn't."
  [test]
  (let [data (expected-value (get test "expected"))
        name (get test "name")]
    (if (get test "must_fail")
      (is (= ::sfv/invalid (support/thrown #(sfv/serialize (type-of test) data))) name)
      (is (= (canonical test) (sfv/serialize (type-of test) data)) name))))

(deftest suite-parse
  (doseq [file  parse-files
          test  (suite file)]
    (testing file
      (check-parse test))))

(deftest suite-serialize
  (doseq [file serialisation-files
          test (suite (str "serialisation-tests/" file))]
    (testing file
      (check-serialize test))))

(deftest suite-is-there
  (testing "dev/fetch.sh has downloaded the suite"
    (is (some? (suite "item")))))

(deftest field-lines
  (is (= [[1 []] [2 []]] (sfv/parse :list ["1" "2"])))
  (is (nil? (sfv/parse :item nil))))

(deftest lenient-padding
  (testing "RFC 9530's examples have more padding than they need"
    (is (= 32 (bytes/length (first (sfv/parse :item ":RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg==:")))))))

(deftest serialization-of-plain-values
  (is (= "sha-256=:aGVsbG8=:, q" (sfv/serialize :dictionary {"sha-256" (bytes/encode "hello") "q" true})))
  (is (= "a;b=?0, (1 2);c" (sfv/serialize :list [['a {"b" false}] [[1 2] {"c" true}]])))
  (is (= "1.5" (sfv/serialize :item (sfv/decimal 1.5))))
  (is (= ::sfv/invalid (support/thrown #(sfv/serialize :item 1.5))))
  (is (= "%\"f%c3%bc%25\"" (sfv/serialize :item (sfv/display-string "fü%")))))
