;;;; test/records-tests.lisp — round-trip every record type through a message.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun round-trip-record (record)
  "Encode RECORD as the sole answer of a message, decode, return the decoded record."
  (let* ((msg (make-dns-message :answers (list record)))
         (decoded (decode-message (encode-message msg))))
    (first (dns-message-answers decoded))))

(test a-record-round-trips
  (let ((d (round-trip-record
            (make-instance 'a-record :name "host.local"
                                     :address (parse-ipv4 "10.0.0.7")))))
    (is (typep d 'a-record))
    (is (equalp (parse-ipv4 "10.0.0.7") (a-address d)))))

(test aaaa-record-round-trips
  (let* ((addr (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xfe #x80 0 0 0 0 0 0
                                                  2 3 4 5 6 7 8 9)))
         (d (round-trip-record
             (make-instance 'aaaa-record :name "host.local" :address addr))))
    (is (typep d 'aaaa-record))
    (is (equalp addr (aaaa-address d)))))

(test ptr-record-round-trips
  (let ((d (round-trip-record
            (make-instance 'ptr-record :name "_ipp._tcp.local"
                                       :target "Printer._ipp._tcp.local"))))
    (is (typep d 'ptr-record))
    (is (string= "Printer._ipp._tcp.local" (ptr-target d)))))

(test srv-record-round-trips
  (let ((d (round-trip-record
            (make-instance 'srv-record :name "Printer._ipp._tcp.local"
                                       :priority 0 :weight 0 :port 631
                                       :target "host.local"))))
    (is (typep d 'srv-record))
    (is (= 631 (srv-port d)))
    (is (string= "host.local" (srv-target d)))))

(test txt-record-round-trips
  (let ((d (round-trip-record
            (make-instance 'txt-record :name "Printer._ipp._tcp.local"
                                       :strings '("path=/ipp/print" "rp=ipp/print"
                                                  "air=none")))))
    (is (typep d 'txt-record))
    (is (equal '("path=/ipp/print" "rp=ipp/print" "air=none") (txt-strings d)))))

(test unknown-record-round-trips
  ;; An unmodeled rrtype decodes to UNKNOWN-RECORD with its raw rdata intact.
  (let* ((rdata (make-array 3 :element-type '(unsigned-byte 8)
                             :initial-contents '(1 2 3)))
         (d (round-trip-record
             (make-instance 'unknown-record :name "x.local" :rtype 99
                                            :ttl 120 :rdata rdata))))
    (is (typep d 'unknown-record))
    (is (= 99 (rr-type d)))
    (is (equalp rdata (rr-rdata d)))))

(test nsec-record-round-trips
  ;; A name that has A + SRV + TXT but not AAAA — the mDNS way to say
  ;; "don't bother asking for the IPv6 address".
  (let ((d (round-trip-record
            (make-instance 'nsec-record :name "host.local"
                                        :next-name "host.local"
                                        :types (list +type-a+ +type-srv+ +type-txt+)))))
    (is (typep d 'nsec-record))
    (is (string= "host.local" (nsec-next-name d)))
    (is (equal (list +type-a+ +type-txt+ +type-srv+)   ; returned sorted ascending
               (sort (copy-list (nsec-types d)) #'<)))))
