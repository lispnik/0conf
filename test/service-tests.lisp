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
    (is (= 4 (length records)))
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
