;;;; test/codec-tests.lisp — round-trip tests for the wire codec.

(in-package #:0conf/test)

(def-suite 0conf-tests :description "0conf codec test suite.")
(in-suite 0conf-tests)

(defun run-tests ()
  "Entry point used by (asdf:test-system :0conf).  Signals on failure."
  (let ((0conf::*response-delay* nil)      ; no artificial sleeps under test
        (0conf::*announce-interval* 0))
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

(test label-escaping-round-trips
  ;; RFC 4343 presentation form: dots and backslashes inside a label are escaped.
  (is (string= "a\\.b" (0conf::escape-label "a.b")))
  (is (string= "a\\\\b" (0conf::escape-label "a\\b")))
  (is (string= "plain" (0conf::escape-label "plain")))
  ;; split-name unescapes and splits only on unescaped dots
  (is (equal '("a.b" "c") (0conf::split-name "a\\.b.c")))
  (is (equal '("a\\b") (0conf::split-name "a\\\\b")))
  (is (equal '("host" "local") (0conf::split-name "host.local"))))

(test name-with-dotted-label-round-trips
  ;; A label containing a literal dot survives the wire and comes back escaped.
  (let* ((escaped "My Printer 2\\.0._ipp._tcp.local")
         (w (make-writer)))
    (write-name w escaped)
    (is (string= escaped (read-name (make-reader (writer-result w)))))))

(test parse-ipv6-embedded-ipv4
  (flet ((v (&rest bytes)
           (make-array 16 :element-type '(unsigned-byte 8) :initial-contents bytes)))
    (is (equalp (v 0 0 0 0 0 0 0 0 0 0 #xff #xff 1 2 3 4) (parse-ipv6 "::ffff:1.2.3.4")))
    (is (equalp (v 0 0 0 0 0 0 0 0 0 0 0 0 1 2 3 4) (parse-ipv6 "::1.2.3.4")))
    (is (equalp (v 0 #x64 #xff #x9b 0 0 0 0 0 0 0 0 1 2 3 4)
                (parse-ipv6 "64:ff9b::1.2.3.4")))))

(test read-name-normalizes-to-nfc
  ;; A wire name whose bytes are decomposed é decodes to the composed (NFC) form.
  (let* ((decomposed (coerce (list #\e (code-char #x301)) 'string))
         (label (0conf::string->octets decomposed))
         (wire (concatenate '(vector (unsigned-byte 8))
                            (vector (length label)) label (vector 0)))
         (name (read-name (make-reader (coerce wire '(simple-array (unsigned-byte 8) (*)))))))
    (is (string= (coerce (list (code-char #xe9)) 'string) name))))

(test decode-survives-truncation
  "Truncating a valid message at any prefix length decodes or signals cleanly —
never a raw array-index error or corrupt data (the reader is bounds-checked)."
  (let* ((full (encode-message
                (make-dns-message
                 :id 1
                 :questions (list (make-question :name "_x._tcp.local" :qtype +type-ptr+))
                 :answers (list (make-instance 'a-record :name "h.local"
                                               :address (parse-ipv4 "1.2.3.4"))))))
         (handled 0))
    (dotimes (n (1+ (length full)))
      (handler-case (progn (decode-message (subseq full 0 n)) (incf handled))
        (error () (incf handled))))
    (is (= (1+ (length full)) handled))))

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

;;; --- packet size discipline (RFC 6762 §17 / §7.2) --------------------------

(defun response-of (records &optional first)
  "The DNS-MESSAGE a group of RECORDS would be sent as — the shape CHUNK-RECORDS
measures against."
  (declare (ignore first))
  (make-dns-message :flags +flag-response+ :answers records))

(test chunk-records-fills-packets-without-losing-any
  "Every group fits the budget, and concatenating them gives back the input in
order — nothing dropped, nothing duplicated."
  (let* ((records (loop for i from 0 below 100
                        collect (make-instance 'a-record
                                               :name (format nil "host~D.local" i)
                                               :cache-flush t :ttl 120
                                               :address (parse-ipv4 "10.0.0.1"))))
         (groups (0conf::chunk-records records 0conf::*max-message-size* #'response-of)))
    (is (> (length groups) 1))
    (is (every (lambda (g)
                 (<= (length (encode-message (response-of g))) 0conf::*max-message-size*))
               groups))
    (is (equal records (apply #'append groups)))))

(test an-oversized-record-gets-a-packet-to-itself
  "RFC 6762 §17: a record too large to share a datagram travels alone, and the
records around it still pack normally."
  (let* ((big (make-instance 'txt-record :name "big._x._tcp.local"
                             :cache-flush t :ttl 120
                             :strings (loop repeat 40
                                            collect (format nil "k=~A"
                                                            (make-string 200
                                                                         :initial-element #\y)))))
         (small (make-instance 'a-record :name "h.local" :cache-flush t :ttl 120
                               :address (parse-ipv4 "10.0.0.1")))
         (groups (0conf::chunk-records (list small big small)
                                       0conf::*max-message-size* #'response-of)))
    (is (> (length (encode-message (response-of (list big)))) 0conf::*max-message-size*))
    (is (= 3 (length groups)))
    (is (equal (list big) (second groups)))))

(test known-answer-query-splits-with-the-tc-bit
  "RFC 6762 §7.2: the question rides in the first packet only, every packet but
the last sets TC, and no known answer is lost."
  (let* ((known (loop for i from 0 below 200
                      collect (make-instance 'ptr-record :name "_ipp._tcp.local" :ttl 4500
                                             :target (format nil "Printer Number ~D._ipp._tcp.local" i))))
         (question (make-question :name "_ipp._tcp.local" :qtype +type-ptr+))
         (packets (0conf::known-answer-query-packets (list question) known))
         (messages (mapcar #'decode-message packets)))
    (is (> (length packets) 1))
    (is (every (lambda (p) (<= (length p) 0conf::*max-message-size*)) packets))
    (is (= 1 (length (dns-message-questions (first messages)))))
    (is (every (lambda (m) (null (dns-message-questions m))) (rest messages)))
    (is (every #'0conf::message-truncated-p (butlast messages)))
    (is (not (0conf::message-truncated-p (car (last messages)))))
    (is (= (length known)
           (loop for m in messages sum (length (dns-message-answers m)))))))

(test known-answer-query-with-nothing-known-is-a-single-packet
  "The common case must not regress into an empty extra packet."
  (let* ((question (make-question :name "_ipp._tcp.local" :qtype +type-ptr+))
         (packets (0conf::known-answer-query-packets (list question) '())))
    (is (= 1 (length packets)))
    (let ((m (decode-message (first packets))))
      (is (= 1 (length (dns-message-questions m))))
      (is (null (dns-message-answers m)))
      (is (not (0conf::message-truncated-p m))))))

(test chunking-bisects-instead-of-encoding-once-per-record
  "Appending a record can only lengthen the encoding — compression never shrinks
what came before — so the fit is monotonic and can be bisected.  The linear walk
this replaces cost one full re-encode per record appended, on the listener thread
inside the reply path."
  (let* ((records (loop for i from 0 below 200
                        collect (make-instance 'a-record
                                               :name (format nil "host~D.local" i)
                                               :cache-flush t :ttl 120
                                               :address (parse-ipv4 "10.0.0.1"))))
         (calls 0)
         (groups (0conf::chunk-records records 0conf::*max-message-size*
                                       (lambda (g first)
                                         (incf calls)
                                         (response-of g first)))))
    ;; Same split as before, nothing lost or reordered ...
    (is (equal records (apply #'append groups)))
    (is (every (lambda (g)
                 (<= (length (encode-message (response-of g))) 0conf::*max-message-size*))
               groups))
    ;; ... for fewer encodes than there are records.
    (is (< calls (length records)))))
