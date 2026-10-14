(ns ^:no-doc dk.simongray.httpsig.impl.sfv
  "The algorithms of structured fields by RFC 9651, section 4: parsing the
  text of a field into data, and serializing data into text.

  Each step of parsing is a function of the text `s` and the index `i` that
  it starts at, and returns a pair of its value and the index after it. A
  step throws ::sfv/invalid when the text isn't what it reads. Each step
  of serializing returns text, and throws ::sfv/invalid for a value that
  it can't serialize."
  (:refer-clojure :exclude [parse-boolean])
  (:require [clojure.string :as str]
            [dk.simongray.httpsig.sfv :as-alias sfv]
            [dk.simongray.webcrypto.bytes :as bytes])
  #?(:clj (:import [java.math BigDecimal]
                   [java.nio ByteBuffer]
                   [java.nio.charset CharacterCodingException CodingErrorAction
                                     StandardCharsets])))

(defrecord ^{:doc "A Decimal of RFC 9651, whose :value is a number."}
  Decimal [value])

(defrecord ^{:doc "A Display String of RFC 9651, whose :text is a string."}
  DisplayString [text])

(defn invalid
  "The exception of text or data that isn't a structured field, for the
  reason `why`."
  [why]
  (ex-info why {:type ::sfv/invalid}))

(defn code-at
  "The code of the character at `i` in the text `s`, or -1 past its end."
  [^String s i]
  (if (< i (count s))
    #?(:clj  (int (.charAt s (int i)))
       :cljs (.charCodeAt s i))
    -1))

;; RFC 5234, appendix B.1
(defn digit?
  "Whether the character `c` is a DIGIT."
  [c]
  (<= 0x30 c 0x39))

(defn alpha?
  "Whether the character `c` is an ALPHA."
  [c]
  (or (<= 0x41 c 0x5A) (<= 0x61 c 0x7A)))

(defn lcalpha?
  "Whether the character `c` is a lower-case ALPHA."
  [c]
  (<= 0x61 c 0x7A))

;; RFC 9110, section 5.6.2
(defn tchar?
  "Whether the character `c` is a tchar of HTTP."
  [c]
  (or (digit? c)
      (alpha? c)
      (contains? #{0x21 0x23 0x24 0x25 0x26 0x27 0x2A 0x2B 0x2D 0x2E 0x5E 0x5F
                   0x60 0x7C 0x7E}
                 c)))

;; RFC 9651, section 3.1.2: lcalpha / DIGIT / "_" / "-" / "." / "*"
(defn key-char?
  "Whether the character `c` can be in a key."
  [c]
  (or (lcalpha? c) (digit? c) (contains? #{0x5F 0x2D 0x2E 0x2A} c)))

;; RFC 9651, section 3.3.3: VCHAR or SP
(defn visible?
  "Whether the character `c` is visible ASCII or a space."
  [c]
  (<= 0x20 c 0x7E))

(defn skip
  "The index of the first character at or after `i` in the text `s` that
  isn't one of the codes `cs`."
  [s i cs]
  (if (contains? cs (code-at s i))
    (recur s (inc i) cs)
    i))

(def sp
  "The code of SP."
  #{0x20})

(def ows
  "The codes of OWS: SP and HTAB."
  #{0x20 0x09})

(defn expect
  "The index after the character `c` at `i` in the text `s`, for the reason
  `why` when the character isn't there."
  [s i c why]
  (if (= c (code-at s i))
    (inc i)
    (throw (invalid why))))

(defn parse-number
  "The number that the decimal digits `s` name, with a sign of `sign`."
  [s sign decimal?]
  (* sign #?(:clj  (if decimal? (Double/parseDouble s) (Long/parseLong s))
             :cljs (if decimal? (js/parseFloat s) (js/parseInt s 10)))))

;; RFC 9651, section 4.2.4
(defn parse-integer-or-decimal
  "An Integer or a Decimal at `i` in the text `s`."
  [s i]
  (let [negative? (= 0x2D (code-at s i))
        start     (cond-> i negative? inc)
        _         (when-not (digit? (code-at s start))
                    (throw (invalid "A number starts with a digit")))
        end       (loop [j start dot nil]
                    (let [c (code-at s j)]
                      (cond
                        (digit? c)
                        (let [n (- (inc j) start)]
                          (when (if dot (> n 16) (> n 15))
                            (throw (invalid "A number has too many digits")))
                          (recur (inc j) dot))

                        (and (= 0x2E c) (not dot))
                        (do (when (> (- j start) 12)
                              (throw (invalid "A Decimal has at most 12 digits before its point")))
                            (recur (inc j) j))

                        :else
                        [j dot])))
        [j dot]   end
        digits    (subs s start j)
        sign      (if negative? -1 1)]
    (if dot
      (let [fraction (- j dot 1)]
        (when-not (<= 1 fraction 3)
          (throw (invalid "A Decimal has one to three digits after its point")))
        [(->Decimal (parse-number digits sign true)) j])
      [(parse-number digits sign false) j])))

;; RFC 9651, section 4.2.5
(defn parse-string
  "A String at `i` in the text `s`."
  [s i]
  (loop [j     (expect s i 0x22 "A String starts with a quote")
         start j
         parts []]
    (let [c (code-at s j)]
      (cond
        (= 0x5C c)
        (let [escaped (code-at s (inc j))]
          (when-not (contains? #{0x22 0x5C} escaped)
            (throw (invalid "A backslash in a String escapes a quote or a backslash")))
          (recur (+ j 2) (+ j 2) (conj parts (subs s start j) (subs s (inc j) (+ j 2)))))

        (= 0x22 c)
        [(apply str (conj parts (subs s start j))) (inc j)]

        (= -1 c)
        (throw (invalid "A String ends with a quote"))

        (not (visible? c))
        (throw (invalid "A String holds visible ASCII and spaces alone"))

        :else
        (recur (inc j) start parts)))))

;; RFC 9651, section 4.2.6
(defn parse-token
  "A Token at `i` in the text `s`, as a symbol."
  [s i]
  (let [c (code-at s i)]
    (when-not (or (alpha? c) (= 0x2A c))
      (throw (invalid "A Token starts with a letter or *")))
    (let [end (loop [j (inc i)]
                (let [c (code-at s j)]
                  (if (or (tchar? c) (= 0x3A c) (= 0x2F c))
                    (recur (inc j))
                    j)))]
      [(symbol (subs s i end)) end])))

(def base64-digits
  "The digits of base64, in the order of their values."
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

;; RFC 4648, section 3.5: the bits of the last digit that no byte takes
(defn without-pad-bits
  "The base64 `digits`, without padding, with the pad bits of the last digit
  set to zero."
  [digits]
  (let [n    (count digits)
        mask (case (int (mod n 4)) 2 0x30 3 0x3C 0x3F)
        d    (str/index-of base64-digits (subs digits (max 0 (dec n))))]
    (if (and d (pos? n))
      (str (subs digits 0 (dec n)) (subs base64-digits (bit-and d mask) (inc (bit-and d mask))))
      digits)))

(defn padded
  "The base64 `digits` with the padding that makes their length a multiple
  of four."
  [digits]
  (str digits (case (int (mod (count digits) 4)) 2 "==" 3 "=" "")))

(defn trailing-pads
  "The number of = at the end of the text `s`."
  [s]
  (loop [n 0]
    (if (and (< n (count s)) (= 0x3D (code-at s (- (count s) n 1))))
      (recur (inc n))
      n)))

;; RFC 9651, section 4.2.7: parsers SHOULD NOT fail on missing padding or
;; pad bits that aren't zero, and RFC 9530's own examples over-pad
(defn base64-bytes
  "The bytes of the base64 text `s` of a Byte Sequence, or nil when it isn't
  base64. The padding can be missing or longer than it needs to be, and the
  pad bits needn't be zero."
  [s]
  (let [digits (subs s 0 (- (count s) (trailing-pads s)))]
    (when (and (not (str/includes? digits "="))
               (not= 1 (mod (count digits) 4)))
      (bytes/from-base64 (padded (without-pad-bits digits))))))

(defn parse-byte-sequence
  "A Byte Sequence at `i` in the text `s`, as bytes."
  [s i]
  (let [start (expect s i 0x3A "A Byte Sequence starts with a colon")
        end   (or (str/index-of s ":" start)
                  (throw (invalid "A Byte Sequence ends with a colon")))
        text  (subs s start end)]
    (when-not (every? #(or (alpha? %) (digit? %) (contains? #{0x2B 0x2F 0x3D} %))
                      (map #(code-at text %) (range (count text))))
      (throw (invalid "A Byte Sequence holds the digits of base64 alone")))
    [(or (base64-bytes text)
         (throw (invalid "A Byte Sequence is base64")))
     (inc end)]))

;; RFC 9651, section 4.2.8
(defn parse-boolean
  "A Boolean at `i` in the text `s`."
  [s i]
  (let [j (expect s i 0x3F "A Boolean starts with a question mark")]
    (case (int (code-at s j))
      0x31 [true (inc j)]
      0x30 [false (inc j)]
      (throw (invalid "A Boolean is ?1 or ?0")))))

(def max-date-seconds
  "The most seconds from the epoch that a Date can be, in either direction,
  here: those of the largest Date of JavaScript, 8.64e15 milliseconds.
  RFC 9651 allows larger ones, but every platform refuses what any refuses."
  8640000000000)

(defn instant
  "The inst `seconds` after the epoch."
  [seconds]
  #?(:clj  (java.util.Date. (long (* 1000 seconds)))
     :cljs (js/Date. (* 1000 seconds))))

;; RFC 9651, section 4.2.9
(defn parse-date
  "A Date at `i` in the text `s`, as an inst."
  [s i]
  (let [[n j] (parse-integer-or-decimal s (expect s i 0x40 "A Date starts with @"))]
    (when-not (integer? n)
      (throw (invalid "A Date is a number of whole seconds")))
    (when (> (abs n) max-date-seconds)
      (throw (invalid "A Date is beyond what the library takes")))
    [(instant n) j]))

(defn lower-hex?
  "Whether the character `c` is a digit of hexadecimal in lower case."
  [c]
  (or (digit? c) (<= 0x61 c 0x66)))

(defn utf-8
  "The text of the UTF-8 bytes `b`, or nil when they aren't UTF-8. A byte
  order mark stays in the text."
  [^bytes b]
  #?(:clj  (try
             (-> (.newDecoder StandardCharsets/UTF_8)
                 (.onMalformedInput CodingErrorAction/REPORT)
                 (.onUnmappableCharacter CodingErrorAction/REPORT)
                 (.decode (ByteBuffer/wrap b))
                 str)
             (catch CharacterCodingException _
               nil))
     :cljs (try
             (.decode (js/TextDecoder. "utf-8" #js {:fatal true :ignoreBOM true}) b)
             (catch :default _
               nil))))

;; RFC 9651, section 4.2.10
(defn parse-display-string
  "A Display String at `i` in the text `s`."
  [s i]
  (loop [j     (expect s (expect s i 0x25 "A Display String starts with %")
                       0x22 "A Display String starts with %\"")
         codes []]
    (let [c (code-at s j)]
      (cond
        (not (visible? c))
        (throw (invalid "A Display String ends with a quote, and holds visible ASCII and spaces"))

        (= 0x25 c)
        (let [hi (code-at s (inc j))
              lo (code-at s (+ j 2))]
          (when-not (and (lower-hex? hi) (lower-hex? lo))
            (throw (invalid "A Display String escapes a byte as % and two hexadecimal digits in lower case")))
          (recur (+ j 3) (conj codes #?(:clj  (Integer/parseInt (subs s (inc j) (+ j 3)) 16)
                                        :cljs (js/parseInt (subs s (inc j) (+ j 3)) 16)))))

        (= 0x22 c)
        [(->DisplayString (or (utf-8 (bytes/of codes))
                              (throw (invalid "A Display String is UTF-8"))))
         (inc j)]

        :else
        (recur (inc j) (conj codes c))))))

;; RFC 9651, section 4.2.3.1
(defn parse-bare-item
  "A bare item at `i` in the text `s`."
  [s i]
  (let [c (code-at s i)]
    (cond
      (or (= 0x2D c) (digit? c)) (parse-integer-or-decimal s i)
      (= 0x22 c)                 (parse-string s i)
      (or (= 0x2A c) (alpha? c)) (parse-token s i)
      (= 0x3A c)                 (parse-byte-sequence s i)
      (= 0x3F c)                 (parse-boolean s i)
      (= 0x40 c)                 (parse-date s i)
      (= 0x25 c)                 (parse-display-string s i)
      :else                      (throw (invalid "A bare item is a number, a String, a Token, a Byte Sequence, a Boolean, a Date or a Display String")))))

;; RFC 9651, section 4.2.3.3
(defn parse-key
  "A key at `i` in the text `s`."
  [s i]
  (let [c (code-at s i)]
    (when-not (or (lcalpha? c) (= 0x2A c))
      (throw (invalid "A key starts with a lower-case letter or *")))
    (let [end (loop [j (inc i)]
                (if (key-char? (code-at s j)) (recur (inc j)) j))]
      [(subs s i end) end])))

(defn assoc-pair
  "The `pairs` of an ordered map with `k` set to `v`: where it is when the
  pairs have it already, and else at the end. The `index` maps each key to
  its place in the pairs, and the result is a pair of both."
  [[pairs index] k v]
  (if-let [n (get index k)]
    [(assoc pairs n [k v]) index]
    [(conj pairs [k v]) (assoc index k (count pairs))]))

;; RFC 9651, section 4.2.3.2
(defn parse-parameters
  "The Parameters at `i` in the text `s`, as pairs of a key and a value."
  [s i]
  (loop [i i acc [[] {}]]
    (if (= 0x3B (code-at s i))
      (let [[k j] (parse-key s (skip s (inc i) sp))
            [v j] (if (= 0x3D (code-at s j))
                    (parse-bare-item s (inc j))
                    [true j])]
        (recur j (assoc-pair acc k v)))
      [(first acc) i])))

;; RFC 9651, section 4.2.3
(defn parse-item
  "An Item at `i` in the text `s`, as a pair of its value and its
  parameters."
  [s i]
  (let [[v j]      (parse-bare-item s i)
        [params j] (parse-parameters s j)]
    [[v params] j]))

;; RFC 9651, section 4.2.1.2
(defn parse-inner-list
  "An Inner List at `i` in the text `s`, as a pair of its items and its
  parameters."
  [s i]
  (loop [j     (expect s i 0x28 "An Inner List starts with a parenthesis")
         items []]
    (let [j (skip s j sp)]
      (case (int (code-at s j))
        0x29 (let [[params j] (parse-parameters s (inc j))]
               [[items params] j])
        -1   (throw (invalid "An Inner List ends with a parenthesis"))
        (let [[item j] (parse-item s j)]
          (when-not (contains? #{0x20 0x29} (code-at s j))
            (throw (invalid "The items of an Inner List are apart by spaces")))
          (recur j (conj items item)))))))

;; RFC 9651, section 4.2.1.1
(defn parse-item-or-inner-list
  "An Item or an Inner List at `i` in the text `s`."
  [s i]
  (if (= 0x28 (code-at s i))
    (parse-inner-list s i)
    (parse-item s i)))

(defn after-member
  "The index of the next member after the one that ends at `i` in the text
  `s`, or nil at the end of the text."
  [s i]
  (let [i (skip s i ows)]
    (cond
      (= i (count s))     nil
      (not= 0x2C (code-at s i)) (throw (invalid "The members of a List or a Dictionary are apart by commas"))
      :else               (let [j (skip s (inc i) ows)]
                            (if (= j (count s))
                              (throw (invalid "A List or a Dictionary doesn't end with a comma"))
                              j)))))

;; RFC 9651, section 4.2.1
(defn parse-list
  "A List at `i` in the text `s`, as a vector of its members."
  [s i]
  (loop [i i members []]
    (if (= i (count s))
      [members i]
      (let [[member j] (parse-item-or-inner-list s i)
            members    (conj members member)]
        (if-let [next-i (after-member s j)]
          (recur next-i members)
          [members (count s)])))))

;; RFC 9651, section 4.2.2
(defn parse-dictionary
  "A Dictionary at `i` in the text `s`, as pairs of a key and a member."
  [s i]
  (loop [i i acc [[] {}]]
    (if (= i (count s))
      [(first acc) i]
      (let [[k j]      (parse-key s i)
            [member j] (if (= 0x3D (code-at s j))
                         (parse-item-or-inner-list s (inc j))
                         (let [[params j] (parse-parameters s j)]
                           [[true params] j]))
            acc        (assoc-pair acc k member)]
        (if-let [next-i (after-member s j)]
          (recur next-i acc)
          [(first acc) (count s)])))))

(defn ascii?
  "Whether the text `s` holds ASCII alone."
  [s]
  (every? #(< (code-at s %) 0x80) (range (count s))))

;; RFC 9651, section 4.2
(defn parse
  "The field of the `type` (:list, :dictionary or :item) in the text `s`,
  or nil when it isn't one."
  [type s]
  (try
    (when-not (ascii? s)
      (throw (invalid "A structured field is ASCII")))
    (let [step  (case type
                  :list       parse-list
                  :dictionary parse-dictionary
                  :item       parse-item)
          [v i] (step s (skip s 0 sp))]
      (when (= (skip s i sp) (count s))
        v))
    (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
      (when-not (= ::sfv/invalid (:type (ex-data e)))
        (throw e)))))

;; RFC 9651, section 4.1.4
(defn serialize-integer
  "The text of the Integer `n`."
  [n]
  (when-not (<= -999999999999999 n 999999999999999)
    (throw (invalid "An Integer has at most 15 digits")))
  (str n))

(defn plain-decimal
  "The decimal digits of the number `x`, with a sign and a point, without an
  exponent, by the shortest form that reads back as `x`."
  [x]
  #?(:clj  (.toPlainString (BigDecimal/valueOf (double x)))
     :cljs (let [s (str x)]
             (cond
               ;; under 1e-6, which rounds to zero
               (str/includes? s "e-") "0"
               ;; at least 1e21, which is too large
               (str/includes? s "e+") (throw (invalid "A Decimal has at most 12 digits before its point"))
               :else                  s))))

(defn round-up?
  "Whether the `rest` of the digits after the third decimal place round the
  number of thousandths `n` up: when they're more than half, or half and `n`
  is odd."
  [n rest]
  (let [first-digit (code-at rest 0)]
    (cond
      (> first-digit 0x35) true
      (< first-digit 0x35) false
      (some #(not= 0x30 (code-at rest %)) (range 1 (count rest))) true
      :else (odd? n))))

;; RFC 9651, section 4.1.5: round to three decimal places, half to even
(defn thousandths
  "The decimal text `s` without its sign, as a whole number of thousandths,
  rounded half to even."
  [s]
  (let [[whole fraction] (str/split s #"\." 2)
        fraction         (or fraction "")
        kept             (subs (str fraction "000") 0 3)
        rest             (when (> (count fraction) 3) (subs fraction 3))]
    (when (> (count whole) 12)
      (throw (invalid "A Decimal has at most 12 digits before its point")))
    (let [n (parse-number (str whole kept) 1 false)]
      (cond-> n
        (and rest (round-up? n rest)) inc))))

(defn serialize-decimal
  "The text of the number `x` as a Decimal."
  [x]
  (when-not (and (number? x) #?(:clj (Double/isFinite (double x)) :cljs (js/isFinite x)))
    (throw (invalid "A Decimal is a finite number")))
  (let [text  (plain-decimal x)
        n     (thousandths (str/replace text #"^-" ""))
        _     (when (>= n 1000000000000000)
                (throw (invalid "A Decimal has at most 12 digits before its point")))
        whole (quot n 1000)
        part  (str/replace (subs (str (+ 1000 (rem n 1000))) 1) #"0+$" "")]
    (str (when (and (neg? x) (pos? n)) "-")
         whole "." (if (empty? part) "0" part))))

;; RFC 9651, section 4.1.6
(defn serialize-string
  "The text of the String `s`."
  [s]
  (when-not (every? #(visible? (code-at s %)) (range (count s)))
    (throw (invalid "A String holds visible ASCII and spaces alone")))
  (str "\"" (str/escape s {\\ "\\\\" \" "\\\""}) "\""))

;; RFC 9651, section 4.1.7
(defn serialize-token
  "The text of the Token `sym`, a symbol."
  [sym]
  (let [s (str sym)]
    (when-not (and (or (alpha? (code-at s 0)) (= 0x2A (code-at s 0)))
                   (every? #(let [c (code-at s %)] (or (tchar? c) (= 0x3A c) (= 0x2F c)))
                           (range 1 (count s))))
      (throw (invalid (str "A Token is a letter or * and then tchars, colons and slashes, not " s))))
    s))

;; RFC 9651, section 4.1.8
(defn serialize-byte-sequence
  "The text of the Byte Sequence `b`."
  [b]
  (str ":" (bytes/base64 b) ":"))

;; RFC 9651, section 4.1.10
(defn serialize-date
  "The text of the Date `d`, an inst of whole seconds."
  [d]
  (let [ms (inst-ms d)]
    (when-not (zero? (rem ms 1000))
      (throw (invalid "A Date is a number of whole seconds")))
    (when (> (abs (quot ms 1000)) max-date-seconds)
      (throw (invalid "A Date is beyond what the library takes")))
    (str "@" (quot ms 1000))))

(defn hex-byte
  "The byte `b` as two hexadecimal digits in lower case."
  [b]
  (let [n (+ 0x100 (bit-and b 0xFF))]
    (subs #?(:clj (Integer/toHexString n) :cljs (.toString n 16)) 1)))

;; RFC 9651, section 4.1.11
(defn serialize-display-string
  "The text of the Display String of the text `s`."
  [s]
  (let [b (bytes/encode s)]
    (str "%\""
         (apply str (for [i (range (bytes/length b))
                          :let [c (bit-and (bytes/at b i) 0xFF)]]
                      (if (or (= 0x25 c) (= 0x22 c) (not (visible? c)))
                        (str "%" (hex-byte c))
                        #?(:clj (char c) :cljs (js/String.fromCharCode c)))))
         "\"")))

;; RFC 9651, section 4.1.3.1
(defn serialize-bare-item
  "The text of the bare item `x`."
  [x]
  (cond
    (integer? x)                  (serialize-integer x)
    (instance? Decimal x)         (serialize-decimal (:value x))
    (string? x)                   (serialize-string x)
    (symbol? x)                   (serialize-token x)
    (bytes/bytes? x)              (serialize-byte-sequence x)
    (boolean? x)                  (if x "?1" "?0")
    (inst? x)                     (serialize-date x)
    (instance? DisplayString x)   (serialize-display-string (:text x))
    (number? x)                   (throw (invalid (str "A number that isn't an Integer is a Decimal, made by sfv/decimal, not " x)))
    :else                         (throw (invalid (str "A bare item is an integer, a Decimal, a string, a symbol, bytes, a boolean, an inst or a Display String, not " (pr-str x))))))

;; RFC 9651, section 4.1.1.3
(defn serialize-key
  "The text of the key `k`, a string or a keyword."
  [k]
  (let [s (if (keyword? k) (subs (str k) 1) (str k))]
    (when-not (and (or (string? k) (keyword? k))
                   (or (lcalpha? (code-at s 0)) (= 0x2A (code-at s 0)))
                   (every? #(key-char? (code-at s %)) (range 1 (count s))))
      (throw (invalid (str "A key is a lower-case letter or * and then lower-case letters, digits, _, -, . and *, not " (pr-str k)))))
    s))

(defn pairs
  "The pairs of a key and a value in `m`, a map or pairs already."
  [m]
  (cond
    (nil? m)        []
    (map? m)        (seq m)
    (sequential? m) (do (when-not (every? #(and (sequential? %) (= 2 (count %))) m)
                          (throw (invalid "Parameters and Dictionaries are maps or pairs of a key and a value")))
                        m)
    :else           (throw (invalid "Parameters and Dictionaries are maps or pairs of a key and a value"))))

;; RFC 9651, section 4.1.1.2
(defn serialize-parameters
  "The text of the Parameters `params`."
  [params]
  (apply str (for [[k v] (pairs params)]
               (str ";" (serialize-key k) (when-not (true? v)
                                            (str "=" (serialize-bare-item v)))))))

(defn as-member
  "The member `x` of a List or a Dictionary as a pair of its value (or
  items) and its parameters. A value that isn't sequential is an Item
  without parameters."
  [x]
  (if (sequential? x)
    (do (when-not (= 2 (count x))
          (throw (invalid "An Item or an Inner List is a pair of its value and its parameters")))
        x)
    [x nil]))

;; RFC 9651, section 4.1.3
(defn serialize-item
  "The text of the Item `x`."
  [x]
  (let [[v params] (as-member x)]
    (when (sequential? v)
      (throw (invalid "An Item's value isn't sequential")))
    (str (serialize-bare-item v) (serialize-parameters params))))

;; RFC 9651, section 4.1.1.1
(defn serialize-inner-list
  "The text of the Inner List of `items` with the `params`."
  [items params]
  (str "(" (str/join " " (map serialize-item items)) ")"
       (serialize-parameters params)))

(defn serialize-member
  "The text of the member `x` of a List or a Dictionary."
  [x]
  (let [[v params] (as-member x)]
    (if (sequential? v)
      (serialize-inner-list v params)
      (serialize-item [v params]))))

;; RFC 9651, section 4.1.1
(defn serialize-list
  "The text of the List of `members`."
  [members]
  (when-not (or (nil? members) (sequential? members))
    (throw (invalid "A List is sequential")))
  (str/join ", " (map serialize-member members)))

;; RFC 9651, section 4.1.2
(defn serialize-dictionary
  "The text of the Dictionary `m`, a map or pairs of a key and a member."
  [m]
  (str/join ", " (for [[k member] (pairs m)
                       :let [[v params] (as-member member)]]
                   (if (true? v)
                     (str (serialize-key k) (serialize-parameters params))
                     (str (serialize-key k) "=" (serialize-member [v params]))))))

;; RFC 9651, section 4.1
(defn serialize
  "The text of `x` as a field of the `type`: :list, :dictionary or :item."
  [type x]
  (case type
    :list       (serialize-list x)
    :dictionary (serialize-dictionary x)
    :item       (serialize-item x)))
