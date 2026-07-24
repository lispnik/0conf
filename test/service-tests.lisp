;;;; test/service-tests.lisp — DNS-SD expansion + reassembly.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun sample-service ()
  (make-service-info
   :type "_ipp._tcp.local"
   :name "My Printer"
   :host "printbox.local"
   :port 631
   :addresses (list (parse-ipv4 "192.168.1.5"))
   :txt '(("rp" . "ipp/print") ("ty" . "Acme LaserJet") ("air"))))

(test service-instance-name-is-qualified
  (is (string= "My Printer._ipp._tcp.local"
               (service-instance-name (sample-service)))))

(test txt-alist-round-trips
  (let ((alist '(("rp" . "ipp/print") ("air"))))
    (is (equal '("rp=ipp/print" "air") (txt-alist->strings alist)))
    ;; keyless entry comes back with a NIL value
    (is (equal '(("rp" . "ipp/print") ("air" . nil))
               (txt-strings->alist (txt-alist->strings alist))))))

(test service-info-expands-to-ptr-srv-txt-a
  (let* ((records (service-info-records (sample-service)))
         (ptr (find-if (lambda (r) (typep r 'ptr-record)) records))
         (srv (find-if (lambda (r) (typep r 'srv-record)) records))
         (txt (find-if (lambda (r) (typep r 'txt-record)) records))
         (a   (find-if (lambda (r) (typep r 'a-record)) records)))
    ;; PTR, SRV, TXT, A, NSEC(instance), NSEC(host)
    (is (= 6 (length records)))
    ;; PTR: type -> instance, shared (no cache-flush)
    (is (string= "_ipp._tcp.local" (rr-name ptr)))
    (is (string= "My Printer._ipp._tcp.local" (ptr-target ptr)))
    (is (not (rr-cache-flush ptr)))
    ;; SRV: instance -> host:port, unique
    (is (string= "My Printer._ipp._tcp.local" (rr-name srv)))
    (is (= 631 (srv-port srv)))
    (is (string= "printbox.local" (srv-target srv)))
    (is (rr-cache-flush srv))
    ;; TXT + A present and unique
    (is (member "rp=ipp/print" (txt-strings txt) :test #'string=))
    (is (equalp (parse-ipv4 "192.168.1.5") (a-address a)))
    (is (rr-cache-flush a))))

(test service-info-emits-nsec-denials
  "An IPv4-only service gets an NSEC at the instance (SRV+TXT) and at the host
(A only), so listeners don't query for AAAA."
  (let* ((records (service-info-records (sample-service)))
         (nsecs (remove-if-not (lambda (r) (typep r 'nsec-record)) records))
         (instance-nsec (find "My Printer._ipp._tcp.local" nsecs
                              :key #'rr-name :test #'string-equal))
         (host-nsec (find "printbox.local" nsecs
                          :key #'rr-name :test #'string-equal)))
    (is (= 2 (length nsecs)))
    ;; instance NSEC asserts SRV + TXT, nothing else (so no A/AAAA at the instance)
    (is (not (null instance-nsec)))
    (is (equal (list +type-txt+ +type-srv+)
               (sort (copy-list (nsec-types instance-nsec)) #'<)))
    ;; host NSEC asserts A only — the AAAA denial that stops v6 queries
    (is (not (null host-nsec)))
    (is (equal (list +type-a+) (nsec-types host-nsec)))
    (is (not (member +type-aaaa+ (nsec-types host-nsec))))))

(test service-info-nsec-tracks-address-families
  "Dual-stack -> host NSEC lists A and AAAA; no addresses -> no host NSEC."
  (let* ((v6 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
         (dual (make-service-info :type "_x._tcp.local" :name "n" :host "h.local"
                                  :port 1 :addresses (list (parse-ipv4 "10.0.0.1") v6)))
         (none (make-service-info :type "_x._tcp.local" :name "n" :host "h.local"
                                  :port 1 :addresses '()))
         (dual-host-nsec (find "h.local" (service-info-records dual)
                               :key #'rr-name :test #'string-equal
                               :from-end t))
         (none-nsecs (remove-if-not (lambda (r) (typep r 'nsec-record))
                                    (service-info-records none))))
    (is (typep dual-host-nsec 'nsec-record))
    (is (equal (list +type-a+ +type-aaaa+)
               (sort (copy-list (nsec-types dual-host-nsec)) #'<)))
    ;; With no addresses there's only the instance NSEC, no host NSEC.
    (is (= 1 (length none-nsecs)))))

(test service-info-reassembles-ipv6-address
  ;; Exercises the AAAA arm of address reassembly.
  (let* ((v6 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :addresses (list v6)))
         (instance (service-instance-name info))
         (rebuilt (service-info-from-records "_x._tcp.local" instance
                                             (service-info-records info))))
    (is (equalp v6 (first (service-info-addresses rebuilt))))))

(test service-info-reassembles-from-its-own-records
  ;; Round-trip: expand a service to records, then rebuild it from them.
  (let* ((original (sample-service))
         (instance (service-instance-name original))
         (records (service-info-records original))
         (rebuilt (service-info-from-records "_ipp._tcp.local" instance records)))
    (is (not (null rebuilt)))
    (is (string= "My Printer" (service-info-name rebuilt)))
    (is (string= "printbox.local" (service-info-host rebuilt)))
    (is (= 631 (service-info-port rebuilt)))
    (is (equalp (parse-ipv4 "192.168.1.5") (first (service-info-addresses rebuilt))))
    (is (equal '("rp" . "ipp/print")
               (assoc "rp" (service-info-txt rebuilt) :test #'string=)))))
