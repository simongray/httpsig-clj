(ns ^:no-doc dk.simongray.httpsig.impl.date
  "Times as signatures have them: the time now, insts as seconds since the
  epoch, and dates of HTTP as the Date field has them, IMF-fixdate of RFC
  9110, section 5.6.7, e.g. Tue, 20 Apr 2021 02:07:55 GMT."
  #?(:clj (:import [java.time Instant LocalDateTime ZoneOffset]
                   [java.time.format DateTimeFormatter]
                   [java.util Locale])))

(defn now
  "The time now as an inst, by the :now-fn of `opts` when it has one."
  [opts]
  (if-let [now-fn (:now-fn opts)]
    (now-fn)
    #?(:clj (java.util.Date.) :cljs (js/Date.))))

(defn seconds
  "The whole seconds of the inst `t` since the epoch."
  [t]
  (quot (inst-ms t) 1000))

(defn instant
  "The inst `seconds` after the epoch."
  [seconds]
  #?(:clj  (java.util.Date. (long (* 1000 seconds)))
     :cljs (js/Date. (* 1000 seconds))))

#?(:clj
   (def formatter
     "The formatter of IMF-fixdate, with a day of two digits."
     (-> (DateTimeFormatter/ofPattern "EEE, dd MMM yyyy HH:mm:ss 'GMT'" Locale/ENGLISH)
         (.withZone ZoneOffset/UTC))))

;; RFC 9110, section 5.6.7
(defn imf-fixdate
  "The inst `t` as IMF-fixdate."
  [t]
  #?(:clj  (.format ^DateTimeFormatter formatter (Instant/ofEpochMilli (inst-ms t)))
     :cljs (.toUTCString (js/Date. (inst-ms t)))))

(def months
  "The month of each name of IMF-fixdate, from 0."
  (zipmap ["Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"]
          (range)))

(defn utc-instant
  "The inst of the year `y`, the month `m` from 0, the day `d`, and the
  hour `h`, minute `mi` and second `sec` in UTC, or nil when there's no
  such time, e.g. on 31 February."
  [y m d h mi sec]
  #?(:clj  (try
             (java.util.Date/from (.toInstant (LocalDateTime/of (int y) (int (inc m)) (int d)
                                                                (int h) (int mi) (int sec))
                                              ZoneOffset/UTC))
             (catch java.time.DateTimeException _
               nil))
     ;; Date.UTC rolls a day too many over into the next month
     :cljs (let [t (js/Date. (js/Date.UTC y m d h mi sec))]
             (when (and (= m (.getUTCMonth t)) (= d (.getUTCDate t))
                        (= h (.getUTCHours t)) (= mi (.getUTCMinutes t)) (= sec (.getUTCSeconds t)))
               t))))

(defn parse
  "The inst of the IMF-fixdate `s`, or nil when it isn't one. The name of
  the day isn't checked against the date."
  [s]
  (when-let [[_ day month year hour minute second]
             (re-matches #"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT"
                         (str s))]
    (when-let [m (months month)]
      (let [[d y h mi sec] (map parse-long [day year hour minute second])]
        (utc-instant y m d h mi sec)))))
