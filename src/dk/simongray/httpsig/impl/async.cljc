(ns ^:no-doc dk.simongray.httpsig.impl.async
  "Values on the JVM and promises in ClojureScript, beside wary-fetch's
  async namespace: a call whose errors become a promise's rejection, and
  the outcome of a call as data, on the calling thread.")

(defn promised
  "The result of calling `f`: on the JVM the value it returns, and in
  ClojureScript a promise of it, which rejects when `f` throws."
  [f]
  #?(:clj  (f)
     :cljs (js/Promise. (fn [resolve _] (resolve (f))))))

(defn attempt
  "The outcome of calling `f` as a map of its :value, or of the :error that
  it throws (or in ClojureScript rejects with). On the JVM it waits for a
  future that `f` returns, and in ClojureScript it gives a promise.

  Unlike wary-fetch's attempt, it runs `f` on the calling thread."
  [f]
  #?(:clj  (try
             {:value (let [v (f)] (if (future? v) @v v))}
             (catch Exception e
               {:error (or (ex-cause (when (instance? java.util.concurrent.ExecutionException e) e)) e)}))
     :cljs (-> (js/Promise.resolve nil)
               (.then (fn [_] (f)))
               (.then (fn [v] {:value v}))
               (.catch (fn [e] {:error e})))))

(defn error-type
  "The :type of the ex-info `e`, or nil."
  [e]
  (:type (ex-data e)))
