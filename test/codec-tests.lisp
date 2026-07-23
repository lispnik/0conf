;;;; test/codec-tests.lisp — round-trip tests for the wire codec.

(in-package #:0conf/test)

(def-suite 0conf-tests :description "0conf codec test suite.")
(in-suite 0conf-tests)

(defun run-tests ()
  "Entry point used by (asdf:test-system :0conf).  Signals on failure."
  (unless (run! '0conf-tests)
    (error "0conf test suite failed.")))

(test name-compression-round-trips
  "A shared suffix (`local`) should compress on write and decompress on read."
  (let* ((w (make-writer)))
    (write-name w "_ipp._tcp.local")
    (write-name w "printer.local")     ; should reuse the `local` label
    (let* ((bytes (writer-result w))
           (r (make-reader bytes)))
      (is (string= "_ipp._tcp.local" (read-name r)))
      (is (string= "printer.local" (read-name r)))
      ;; Compression really happened: the second name is just "printer" (8 bytes:
      ;; len + 7 chars) followed by a 2-byte pointer, not a full second copy.
      (is (< (length bytes) (+ (length "_ipp._tcp.local")
                               (length "printer.local")
                               10))))))

(test dns-message-round-trips
  "Encode a query+answer message, decode it, and re-encode byte-for-byte."
  (let* ((msg (make-dns-message
               :id 42
               :flags 0
               :questions (list (make-question :name "_ipp._tcp.local"
                                               :qtype +type-ptr+))
               :answers (list (make-instance 'a-record
                                             :name "printer.local"
                                             :cache-flush t
                                             :ttl 120
                                             :address (parse-ipv4 "192.168.1.5")))))
         (bytes (encode-message msg))
         (decoded (decode-message bytes)))
    ;; header
    (is (= 42 (dns-message-id decoded)))
    ;; question
    (is (= 1 (length (dns-message-questions decoded))))
    (let ((q (first (dns-message-questions decoded))))
      (is (string= "_ipp._tcp.local" (question-name q)))
      (is (= +type-ptr+ (question-qtype q))))
    ;; answer
    (is (= 1 (length (dns-message-answers decoded))))
    (let ((a (first (dns-message-answers decoded))))
      (is (typep a 'a-record))
      (is (string= "printer.local" (rr-name a)))
      (is (= 120 (rr-ttl a)))
      (is (rr-cache-flush a))
      (is (equalp (parse-ipv4 "192.168.1.5") (a-address a))))
    ;; Re-encoding the decoded message reproduces the exact bytes — a strong
    ;; check that both directions (incl. name compression) agree.
    (is (equalp bytes (encode-message decoded)))))
