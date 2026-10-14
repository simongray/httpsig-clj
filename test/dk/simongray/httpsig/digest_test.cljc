(ns dk.simongray.httpsig.digest-test
  "The tests of Digest Fields, with the examples of RFC 9530."
  (:require #?(:clj  [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            [dk.simongray.httpsig.digest :as digest]
            [dk.simongray.webcrypto.bytes :as bytes]))

(def hello
  "The content of RFC 9530's examples, {\"hello\": \"world\"}."
  "{\"hello\": \"world\"}")

;; RFC 9530, Appendix D
(deftest sample-digest-values
  (is (= "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
         (digest/field-value hello ["sha-512"])))
  (is (= "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
         (digest/field-value hello))))

;; RFC 9530, section 2 for sha-512, and Appendices B.1 and B.2 for
;; sha-256, over content with an LF (section 2's example of two digests
;; pairs this sha-512 with the sha-256 of B.4's encoded content)
(deftest content-digests
  (is (= "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:, sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:"
         (digest/field-value (str hello "\n") ["sha-256" "sha-512"])))
  (is (= "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
         (digest/field-value nil))
      "the digest of no content"))

;; RFC 9530, Appendix B.4, with the Brotli bytes of erratum 8890, whose
;; first two bytes the RFC prints as 8B 08
(deftest encoded-representation
  (is (= "sha-256=:d435Qo+nKZ+gLcUHn7GQtQ72hiBVAgqoLsZnZPiTGPk=:"
         (digest/field-value (bytes/of [0x0B 0x09 0x80 0x7B 0x22 0x68 0x65 0x6C 0x6C 0x6F
                                        0x22 0x3A 0x20 0x22 0x77 0x6F 0x72 0x6C 0x64 0x22
                                        0x7D 0x0A 0x03])))))

(deftest verification
  (let [signed (digest/with-content-digest {:body hello} ["sha-256" "sha-512"])]
    (is (= {:algorithms ["sha-256" "sha-512"]} (digest/verify signed)))
    (is (= {:algorithms ["sha-256"]} (digest/verify signed {:algorithms #{"sha-256"}})))
    (is (= {:error ::digest/mismatch :algorithm "sha-256"}
           (digest/verify (assoc signed :body "{\"hello\": \"there\"}"))))
    (is (= {:error ::digest/missing} (digest/verify {:body hello})))
    (is (= {:error ::digest/malformed}
           (digest/verify {:headers {"content-digest" "sha-256=\"hex\""} :body hello})))
    (is (= {:error ::digest/unsupported-algorithm}
           (digest/verify {:headers {"Content-Digest" "md5=:Sd/dVLAcvNLSq16eXua5uQ==:"} :body hello}))))
  (testing "RFC 9530, Appendix C.1, whose value has more padding than it needs"
    (is (= {:algorithms ["sha-256"]}
           (digest/verify {:headers {"Content-Digest" "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg==:"}
                           :body    (str hello "\n")})))))

;; RFC 9530, section 4
(deftest wanted-algorithms
  (is (= ["sha-256" "sha-512"] (digest/wanted "sha-512=3, sha-256=10, unixsum=0")))
  (is (= ["sha-256"] (digest/wanted "sha-256=3, sha=10")))
  (is (= [] (digest/wanted "sha-256=0")))
  (is (= [] (digest/wanted "not a dictionary("))))
