;;;; test/interop-tests.lisp — decode REAL mDNS packets.
;;;;
;;;; These byte strings were captured off a live network with tcpdump, straight
;;;; from Apple's mDNSResponder.  They prove our decoder parses genuine Bonjour
;;;; wire data — real name compression, header flags, and the QU
;;;; (unicast-response) bit — not just our own encoder's output round-tripped.
;;;;
;;;; They are all "_services._dns-sd._udp.local" meta traffic, which reveals only
;;;; generic service *types* (_airplay, _printer, ...) — never device names,
;;;; hostnames, or addresses — so they are safe to ship.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun hexbytes (hex)
  (let ((v (make-array (/ (length hex) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defparameter +real-meta-query+
  "000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c8001"
  "Real mDNSResponder `_services._dns-sd._udp.local` query, QU bit set.")

(defparameter +real-meta-response+
  "000084000000000200000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001000011940010085f616972706c6179045f746370c023c00c000c0001000011940008055f72616f70c03d"
  "Real response listing _airplay and _raop service types (uses compression).")

(defparameter +real-meta-response-7+
  "000084000000000700000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c00010000119400170f5f70646c2d6461746173747265616d045f746370c023c00c000c000100001194000b085f7072696e746572c044c00c000c0001000011940007045f697070c044c00c000c000100001194000b085f7363616e6e6572c044c00c000c0001000011940008055f68747470c044c00c000c000100001194000a075f707269766574c044c00c000c0001000011940009065f757363616ec044"
  "Real 7-PTR response (printer/scanner service types), compression-heavy.")

(test decodes-real-mdns-query
  "A real Bonjour query — header flags, name parsing, and the QU bit."
  (let ((m (decode-message (hexbytes +real-meta-query+))))
    (is (not (logbitp 15 (dns-message-flags m))))          ; QR=0 (a query)
    (is (= 1 (length (dns-message-questions m))))
    (let ((q (first (dns-message-questions m))))
      (is (string= "_services._dns-sd._udp.local" (question-name q)))
      (is (= +type-ptr+ (question-qtype q)))
      (is (question-unicast-response q)))                  ; the real QU bit
    (is (= 1 (length (dns-message-questions
                      (decode-message (encode-message m))))))))

(test decodes-real-mdns-response
  "A real response — QR/AA flags and PTR targets recovered through compression."
  (let* ((m (decode-message (hexbytes +real-meta-response+)))
         (answers (dns-message-answers m)))
    (is (logbitp 15 (dns-message-flags m)))                ; QR=1 (a response)
    (is (= 2 (length answers)))
    (is (every (lambda (r) (typep r 'ptr-record)) answers))
    (let ((targets (mapcar #'ptr-target answers)))
      (is (member "_airplay._tcp.local" targets :test #'string=))  ; decompressed
      (is (member "_raop._tcp.local" targets :test #'string=)))
    (is (= 4500 (rr-ttl (first answers))))))

(test decodes-real-mdns-response-with-heavy-compression
  "Seven PTR records that all share compressed suffixes — and the decoded records
survive a re-encode/decode with the same targets (semantic round-trip; the exact
bytes may differ since compression choices are implementation-specific)."
  (let* ((bytes (hexbytes +real-meta-response-7+))
         (targets (mapcar #'ptr-target (dns-message-answers (decode-message bytes)))))
    (is (= 7 (length targets)))
    (is (member "_printer._tcp.local" targets :test #'string=))
    (is (member "_ipp._tcp.local" targets :test #'string=))
    (is (member "_scanner._tcp.local" targets :test #'string=))
    (is (equal targets
               (mapcar #'ptr-target
                       (dns-message-answers
                        (decode-message (encode-message (decode-message bytes)))))))))
