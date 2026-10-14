(ns dk.simongray.httpsig.sfv
  "Structured fields by RFC 9651: the values of HTTP fields such as
  Signature-Input and Content-Digest as data.

  A field is a List, a Dictionary or an Item. The values of RFC 9651 are
  these in Clojure:

  - an Integer, a String or a Boolean is a number, a string or a boolean
  - a Token is a symbol, e.g. sha-256
  - a Byte Sequence is bytes, as webcrypto-clj has them
  - a Date is an inst of whole seconds
  - a Decimal is a record that decimal makes, since JavaScript can't tell
    1.0 from 1
  - a Display String is a record that display-string makes, to tell it
    from a String
  - an Item is a pair of its value and its parameters
  - an Inner List is a pair of a vector of items and its parameters
  - a List is a vector of items and inner lists
  - a Dictionary or Parameters are a vector of pairs of a key and a value,
    which keeps their order

  To serialize, an item without parameters can be its value alone, and
  Parameters and a Dictionary can be maps."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig.impl.sfv :as impl]))

;; RFC 9651, section 4.2
(defn parse
  "The field of the `type` in `s`, or nil when it isn't one. The `type` is
  :list, :dictionary or :item, and `s` is the text of the field or its
  field lines, which join as one value with commas.

  A field that doesn't parse should be ignored, as RFC 9651 says. A Byte
  Sequence parses without its padding, with too much of it, and with pad
  bits that aren't zero.

      (parse :dictionary \"sig1=(\\\"@method\\\");created=1618884473\")
      ;; => [[\"sig1\" [[[\"@method\" []]] [[\"created\" 1618884473]]]]]"
  [type s]
  (some->> (if (string? s) s (some->> (seq s) (str/join ", ")))
           (impl/parse type)))

;; RFC 9651, section 4.1
(defn serialize
  "The text of `x` as a field of the `type`: :list, :dictionary or :item.
  It throws an ex-info of the :type ::invalid for a value that RFC 9651
  can't serialize, e.g. a string with a line break, or a Decimal with more
  than 12 digits before its point.

      (serialize :item ['sha-256 {\"q\" 1}])
      ;; => \"sha-256;q=1\""
  [type x]
  (impl/serialize type x))

(defn decimal
  "The number `x` as a Decimal, which serializes with a point and at most
  three decimal places, rounded half to even."
  [x]
  (impl/->Decimal x))

(defn display-string
  "The text `s` as a Display String, which can hold any Unicode."
  [s]
  (impl/->DisplayString s))

(comment
  (parse :list "sha-256;q=1, (\"@method\" \"@path\");created=1618884473")
  (parse :item ":aGVsbG8:")
  (serialize :dictionary {"sha-256" (impl/base64-bytes "aGVsbG8=")})
  (serialize :item (decimal 9.9995))
  #_.)
