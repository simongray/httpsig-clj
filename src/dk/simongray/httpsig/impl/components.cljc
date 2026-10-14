(ns ^:no-doc dk.simongray.httpsig.impl.components
  "The components of RFC 9421, section 2: the identifiers of the parts of a
  message, their values, and the signature base that they make.

  A component identifier is a pair of its name and its parameters, as an
  Item of structured fields has them, e.g. [\"@query-param\" [[\"name\"
  \"Pet\"]]]. A step that can't find or derive a value throws an ex-info
  whose :type is ::httpsig/missing-component, or ::httpsig/malformed for
  an identifier that RFC 9421 doesn't allow."
  (:require [clojure.string :as str]
            [dk.simongray.httpsig :as-alias httpsig]
            [dk.simongray.httpsig.impl.message :as message]
            [dk.simongray.httpsig.impl.sfv :as sfv]
            [dk.simongray.wary-fetch.url :as wary-url]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.whatwg-url :as url]
            [dk.simongray.whatwg-url.params :as params]
            [dk.simongray.whatwg-url.percent :as percent]))

(defn missing
  "The exception of the component `id` that the message lacks, for the
  reason `why`."
  [id why]
  (ex-info why {:type ::httpsig/missing-component :component id}))

(defn malformed
  "The exception of the component `id` that RFC 9421 doesn't allow, for the
  reason `why`."
  [id why]
  (ex-info why {:type ::httpsig/malformed :component id}))

;; RFC 9421, section 2.2
(def derived-names
  "The names of the derived components, and whether each is of a request or
  a response."
  {"@method"         :request
   "@target-uri"     :request
   "@authority"      :request
   "@scheme"         :request
   "@request-target" :request
   "@path"           :request
   "@query"          :request
   "@query-param"    :request
   "@status"         :response})

;; RFC 9421, section 6.5.2
(def parameter-names
  "The parameters that a component identifier can have."
  #{"sf" "key" "bs" "req" "tr" "name"})

(def field-types
  "The type of each structured field that a component with the sf parameter
  can name, unless the options of a call give more."
  {"accept-signature"    :dictionary
   "cache-status"        :list
   "content-digest"      :dictionary
   "priority"            :dictionary
   "proxy-status"        :list
   "repr-digest"         :dictionary
   "signature"           :dictionary
   "signature-input"     :dictionary
   "want-content-digest" :dictionary
   "want-repr-digest"    :dictionary})

(defn identifier
  "The component `x` as a pair of its name and its parameters as pairs. The
  component is a name, or a pair of a name and its parameters as a map or
  as pairs. A field's name is in lower case."
  [x]
  (let [[component-name params] (if (sequential? x) x [x nil])]
    (when-not (string? component-name)
      (throw (malformed x "A component's name is a string")))
    [(cond-> component-name
       (not (str/starts-with? component-name "@")) str/lower-case)
     (vec (for [[k v] (sfv/pairs params)]
            [(if (keyword? k) (name k) k) v]))]))

(defn parameter
  "The value of the parameter `k` of the component `id`, or nil."
  [[_ params :as id] k]
  (some (fn [[pk v]] (when (= k pk) v)) params))

;; RFC 9421, section 2: the order of the parameters doesn't make two
;; identifiers different
(defn same-identifier
  "The component `id` in a form that compares equal to the same component
  with its parameters in another order."
  [[component-name params]]
  [component-name (set params)])

(defn check-identifier
  "The component `id`, or a throw when RFC 9421 doesn't allow it for a
  message that `response?`."
  [[component-name params :as id] response?]
  (let [flag? #(let [v (parameter id %)] (or (nil? v) (true? v)))]
    (cond
      (= "@signature-params" component-name)
      (throw (malformed id "@signature-params can't be a covered component"))

      (and (str/starts-with? component-name "@") (not (contains? derived-names component-name)))
      (throw (malformed id (str "There's no derived component " component-name)))

      (and (not (str/starts-with? component-name "@"))
           (not= component-name (str/lower-case component-name)))
      (throw (malformed id "The name of a field is in lower case"))

      (some #(not (contains? parameter-names (first %))) params)
      (throw (malformed id (str "A component has the parameters " (str/join ", " (sort parameter-names)))))

      (not-every? flag? ["sf" "bs" "req" "tr"])
      (throw (malformed id "The parameters sf, bs, req and tr are flags"))

      (and (parameter id "bs") (or (parameter id "sf") (parameter id "key")))
      (throw (malformed id "The parameter bs goes with neither sf nor key"))

      (and (parameter id "req") (not response?))
      (throw (malformed id "The parameter req is for a response's signature"))

      (parameter id "tr")
      (throw (missing id "The library reads no trailers"))

      (and (= "@query-param" component-name) (not (string? (parameter id "name"))))
      (throw (malformed id "@query-param has a name"))

      (and (parameter id "name") (not= "@query-param" component-name))
      (throw (malformed id "Only @query-param has a name"))

      (and (str/starts-with? component-name "@")
           (or (parameter id "sf") (parameter id "key") (parameter id "bs")))
      (throw (malformed id "A derived component has none of the parameters sf, key and bs"))

      (and (some? (parameter id "key")) (not (string? (parameter id "key"))))
      (throw (malformed id "The key of a Dictionary member is a string"))

      :else
      id)))

(defn response?
  "Whether the `message` is a response, which has a status."
  [message]
  (contains? message :status))

(defn parsed-url
  "The URL of the request `message`, parsed, or a throw for the component
  `id` when it has none."
  [message id]
  (or (::url message)
      (throw (missing id "The request has no URL"))))

(defn method-name
  "The method of the request `message` as HTTP writes it, e.g. POST. A
  request without one, or with a nil one as wary-fetch prepares it, is a
  GET."
  [message]
  (let [method (or (:method message) :get)]
    (if (keyword? method) (str/upper-case (name method)) (str method))))

;; RFC 9421, section 2.2.8: "percent-encode after encoding" of the
;; form-urlencoded serializer, with a space as %20, as the RFC's example
;; and its editors have it, where whatwg-url writes + for this set alone
(def query-param-set
  "The application/x-www-form-urlencoded percent-encode set, as a function
  of its own, which percent-encodes a space."
  (fn [c] (percent/form-urlencoded-set c)))

(defn query-pairs
  "The parameters of the query of the parsed URL `u` by their names, as
  pairs of names and values, all encoded as @query-param has them."
  [u]
  (let [encode #(percent/encode % query-param-set)]
    (group-by first (for [[k v] (params/parse (or (:query u) ""))]
                      [(encode k) (encode v)]))))

(defn query-param
  "The value of the query parameter of the component `id` in the request
  `message`, encoded."
  [message id]
  (parsed-url message id)
  (let [wanted  (parameter id "name")
        matches (get (::query message) wanted)]
    (case (count matches)
      0 (throw (missing id (str "The query has no parameter " wanted)))
      1 (second (first matches))
      (throw (malformed id (str "The query has the parameter " wanted " more than once"))))))

;; RFC 9421, section 2.2
(defn derived-value
  "The value of the derived component `id` of the `message`."
  [message [component-name :as id]]
  (when (not= (= :response (derived-names component-name)) (response? message))
    (throw (malformed id (str component-name " is a component of a "
                              (name (derived-names component-name))))))
  (case component-name
    "@method"         (method-name message)
    "@target-uri"     (do (parsed-url message id) (str (:url message)))
    "@authority"      (url/host (parsed-url message id))
    "@scheme"         (url/scheme (parsed-url message id))
    "@request-target" (let [u (parsed-url message id)]
                        (str (url/pathname u) (some->> (:query u) (str "?"))))
    "@path"           (let [path (url/pathname (parsed-url message id))]
                        (if (empty? path) "/" path))
    "@query"          (str "?" (:query (parsed-url message id)))
    "@query-param"    (query-param message id)
    "@status"         (str (:status message))))

(defn- trim-start
  "The text `s` without the spaces and tabs at its start."
  [s]
  (subs s (sfv/skip s 0 sfv/ows)))

(defn- trim-end
  "The text `s` without the spaces and tabs at its end."
  [s]
  (loop [end (count s)]
    (if (and (pos? end) (contains? sfv/ows (sfv/code-at s (dec end))))
      (recur (dec end))
      (subs s 0 end))))

;; RFC 9421, section 2.1: leading and trailing whitespace stripped, and
;; obsolete line folding (RFC 9112, section 5.2: OWS CRLF RWS) replaced by
;; a space. A loop rather than a regex, which would backtrack through a
;; long run of spaces at each of its characters.
(defn canonical-line
  "The field line `s` without spaces and tabs around it, and with each
  obsolete line folding in it replaced by a space."
  [s]
  (trim-end
   (trim-start
    (if-not (str/includes? s "\n")
      s
      (let [lines (str/split s #"\r?\n" -1)
            n     (count lines)
            fold? (fn [i] (and (< 0 i n) (contains? sfv/ows (sfv/code-at (nth lines i) 0))))]
        (apply str (for [i (range n)]
                     (str (when (pos? i) (if (fold? i) " " "\n"))
                          (cond-> (nth lines i)
                            (fold? i)       trim-start
                            (fold? (inc i)) trim-end)))))))))

(defn field-lines
  "The lines of the field `field-name` of the `message` as a signature base
  has them, or nil when it has none."
  [message field-name]
  (some->> (message/field-lines (:headers message) field-name)
           (mapv canonical-line)))

;; Each field is read and parsed once, however many components name it, so
;; that the work of a signature base grows with its message and not with
;; the components that a stranger can list, e.g. "x";key="a" "x";key="b".
(defn prepared
  "The `message` with its URL and the query in it parsed, and with each of
  its fields read and parsed on first use, for the components that read
  them."
  [message]
  (let [u        (some-> (:url message) str url/parse)
        lines-of (memoize #(field-lines message %))
        parsed   (memoize (fn [field-name type]
                            (some->> (lines-of field-name)
                                     (str/join ", ")
                                     (sfv/parse type))))]
    (cond-> (assoc message
                   ::field-lines  lines-of
                   ::parsed-field parsed
                   ::members      (memoize #(some->> (parsed % :dictionary) (into {}))))
      u (assoc ::url u ::query (query-pairs u)))))

(defn- not-structured
  "The exception of the field `id` that doesn't parse as its type."
  [[component-name :as id]]
  (missing id (str "The field " component-name " isn't a structured field of its type")))

;; RFC 9421, sections 2.1, 2.1.1, 2.1.2 and 2.1.3
(defn field-value
  "The value of the field `id` of the prepared `message`, with the `types`
  of structured fields for the sf parameter."
  [message [component-name :as id] types]
  (let [lines (or ((::field-lines message) component-name)
                  (throw (missing id (str "The message has no field " component-name))))
        k     (parameter id "key")]
    (cond
      (parameter id "bs")
      (sfv/serialize-list (map bytes/encode lines))

      (some? k)
      (let [members (or ((::members message) component-name)
                        (throw (not-structured id)))]
        (sfv/serialize-member (or (get members k)
                                  (throw (missing id (str "The field " component-name " has no member " k))))))

      (parameter id "sf")
      (let [type (or (get types component-name)
                     (throw (missing id (str "The library doesn't know the type of the field " component-name))))]
        (sfv/serialize type (or ((::parsed-field message) component-name type)
                                (throw (not-structured id)))))

      :else
      (str/join ", " lines))))

;; RFC 9421, section 2.5: printable ASCII, spaces and the tabs that a field
;; can hold, and no line breaks
(defn check-value
  "The `value` of the component `id`, or a throw when it has a character
  that a signature base can't hold."
  [id value]
  (if (every? #(let [c (sfv/code-at value %)] (or (sfv/visible? c) (= 0x09 c)))
              (range (count value)))
    value
    (throw (missing id "The value of a component is ASCII without line breaks; the bs parameter wraps another value"))))

;; RFC 9421, section 2.5, step 2.5
(defn value
  "The value of the component `id` in the prepared `message`, or in the
  prepared :request of `opts` for one with the req parameter. The
  :field-types of `opts` add to the field-types."
  [message id {:keys [request] :as opts}]
  (let [context (if (parameter id "req")
                  (or request (throw (missing id "The response has no request for the req parameter")))
                  message)]
    (check-value id (if (str/starts-with? (first id) "@")
                      (derived-value context id)
                      (field-value context id (merge field-types (:field-types opts)))))))

(defn- with-prepared-request
  "The `opts` of value with their :request prepared."
  [opts]
  (cond-> opts
    (:request opts) (update :request prepared)))

(defn component-value
  "The value of the component `id` in the `message`, by the `opts` of
  value, or a throw when RFC 9421 doesn't allow the component."
  [message id opts]
  (value (prepared message)
         (check-identifier id (response? message))
         (with-prepared-request opts)))

(defn serialize-identifier
  "The text of the component `id` in a signature base."
  [id]
  (sfv/serialize-item id))

;; RFC 9421, section 2.5
(defn signature-base
  "The signature base of the `components` of the `message` with the
  signature `params`, as pairs, by the `opts` of value."
  [message components params opts]
  (let [ids     (map #(check-identifier % (response? message)) components)
        message (prepared message)
        opts    (with-prepared-request opts)]
    (when-not (= (count ids) (count (distinct (map same-identifier ids))))
      (throw (malformed nil "A component is covered once")))
    (str (apply str (for [id ids]
                      (str (serialize-identifier id) ": " (value message id opts) "\n")))
         "\"@signature-params\": " (sfv/serialize-inner-list ids params))))

(defn with-legal-url
  "The request `message` with its URL as the client of each platform sends
  it, so that its @target-uri is the URL on the wire."
  [message]
  (cond-> message
    (and (not (response? message)) (string? (:url message)))
    (update :url wary-url/legal-url)))
