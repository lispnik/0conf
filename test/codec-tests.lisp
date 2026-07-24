;;;; test/codec-tests.lisp — round-trip tests for the wire codec.

(in-package #:0conf/test)

(def-suite 0conf-tests :description "0conf codec test suite.")
(in-suite 0conf-tests)

(defun run-tests ()
  "Entry point used by (asdf:test-system :0conf).  Signals on failure."
  (let ((0conf::*response-delay* nil))     ; no artificial sleeps under test
    (unless (run! '0conf-tests)
      (error "0conf test suite failed."))))

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

(test names-are-nfc-normalized
  "RFC 6762 §16: names go on the wire in NFC, so composed and decomposed
spellings of the same name encode to identical bytes and decode to the composed
form."
  (let* ((composed   (coerce (list (code-char #xe9)) 'string))          ; é (U+00E9)
         (decomposed (coerce (list #\e (code-char #x301)) 'string))     ; e + U+0301
         (name-c (concatenate 'string "caf" composed ".local"))
         (name-d (concatenate 'string "caf" decomposed ".local")))
    ;; Both spellings produce the same wire bytes.
    (let ((wc (make-writer)) (wd (make-writer)))
      (write-name wc name-c)
      (write-name wd name-d)
      (is (equalp (writer-result wc) (writer-result wd))))
    ;; And the decomposed input comes back as the composed (NFC) form.
    (let ((w (make-writer)))
      (write-name w name-d)
      (is (string= name-c (read-name (make-reader (writer-result w))))))))

(test parse-ipv6-handles-compression
  (flet ((v (&rest bytes)
           (make-array 16 :element-type '(unsigned-byte 8) :initial-contents bytes)))
    (is (equalp (v 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1) (parse-ipv6 "::1")))
    (is (equalp (v 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0) (parse-ipv6 "::")))
    (is (equalp (v #xff 2 0 0 0 0 0 0 0 0 0 0 0 0 0 #xfb) (parse-ipv6 "ff02::fb")))
    (is (equalp (v #x20 #x01 #x0d #xb8 0 0 0 0 0 0 0 0 0 0 0 1)
                (parse-ipv6 "2001:db8::1")))
    (is (equalp (v 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)
                (parse-ipv6 "0:0:0:0:0:0:0:1")))))

(test format-ipv6-round-trips
  (is (string= "ff02:0:0:0:0:0:0:fb" (format-ipv6 (parse-ipv6 "ff02::fb")))))

(test format-ipv4-round-trips
  (is (string= "192.168.1.5" (format-ipv4 (parse-ipv4 "192.168.1.5")))))

(test truncation-bit-parsed
  ;; The TC bit (0x0200) survives a round trip and is read back.
  (is (0conf::message-truncated-p
       (decode-message (encode-message (make-dns-message :flags #x0200)))))
  (is (not (0conf::message-truncated-p
            (decode-message (encode-message (make-dns-message :flags 0)))))))

(test malformed-address-input-signals
  (signals error (parse-ipv4 "1.2.3"))                    ; too few octets
  (signals error (parse-ipv6 "1:2:3"))                    ; too few groups
  (signals error (parse-ipv6 "1:2:3:4:5:6:7:8:9"))        ; too many groups
  (signals error (parse-ipv6 "1:2:3:4:5:6:7:8::9")))      ; too many even with ::

(test oversized-label-signals
  ;; A DNS label may be at most 63 octets.
  (signals error
    (write-name (make-writer)
                (concatenate 'string (make-string 64 :initial-element #\a) ".local"))))

(test decode-accepts-non-simple-octets
  ;; DECODE-MESSAGE must copy a non-simple input (list, adjustable vector).
  (let* ((bytes (encode-message (make-dns-message :id 7)))
         (as-list (coerce bytes 'list))
         (adjustable (make-array (length bytes) :element-type '(unsigned-byte 8)
                                                :adjustable t :initial-contents bytes)))
    (is (= 7 (dns-message-id (decode-message as-list))))
    (is (= 7 (dns-message-id (decode-message adjustable))))))

(test message-with-additionals-round-trips
  ;; Exercises the Additional-section write/read paths.
  (let* ((msg (make-dns-message
               :answers (list (make-instance 'a-record :name "h.local"
                                             :address (parse-ipv4 "10.0.0.1")))
               :additionals (list (make-instance 'a-record :name "h2.local"
                                                 :address (parse-ipv4 "10.0.0.2")))))
         (d (decode-message (encode-message msg))))
    (is (= 1 (length (dns-message-additionals d))))
    (is (string= "h2.local" (rr-name (first (dns-message-additionals d)))))))

(test read-name-rejects-bad-pointers
  "Malformed compression pointers must signal, not loop forever."
  (flet ((octets (&rest bytes)
           (make-array (length bytes) :element-type '(unsigned-byte 8)
                                      :initial-contents bytes)))
    ;; self-pointer: offset 0 -> 0
    (signals error (read-name (make-reader (octets #xc0 #x00))))
    ;; forward pointer: offset 0 -> 5
    (signals error (read-name (make-reader (octets #xc0 #x05 0 0 0 0))))
    ;; truncated pointer: high byte with no low byte
    (signals error (read-name (make-reader (octets #xc0))))
    ;; label length runs past the end of the buffer
    (signals error (read-name (make-reader (octets #x05 #x61 #x62))))
    ;; a label with no terminating root — reader runs off the end
    (signals error (read-name (make-reader (octets #x01 #x61))))))

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
