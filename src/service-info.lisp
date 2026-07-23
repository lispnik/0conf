;;;; service-info.lisp — DNS-SD service description + record expansion (RFC 6763).
;;;;
;;;; A SERVICE-INFO fully describes one advertised instance.  Expanding it yields
;;;; the PTR + SRV + TXT + A/AAAA record set that the responder announces, and
;;;; that a browser reassembles on the far side.  Analog of python-zeroconf's
;;;; _services/info.py.

(in-package #:0conf)

;;; DNS-SD conventions: shared records (PTR) get a long ttl; the host records
;;; that identify *this* machine get a short one so stale data clears quickly.
(defparameter *default-other-ttl* 4500)   ; PTR / TXT
(defparameter *default-host-ttl*  120)     ; SRV / A / AAAA

(defstruct (service-info (:constructor make-service-info))
  (type "" :type string)          ; e.g. "_ipp._tcp.local"
  (name "" :type string)          ; instance label, e.g. "My Printer"
  (host "" :type string)          ; e.g. "myhost.local"
  (port 0  :type (unsigned-byte 16))
  (addresses '())                 ; list of 4- or 16-octet vectors
  (txt '())                       ; alist (key . value-string); value NIL = keyless
  (priority 0)
  (weight 0))

(defun service-instance-name (info)
  "\"My Printer._ipp._tcp.local\" — the fully-qualified instance name."
  (format nil "~A.~A" (service-info-name info) (service-info-type info)))

(defun txt-alist->strings (alist)
  "Turn ((\"path\" . \"/admin\") (\"paperless\")) into (\"path=/admin\" \"paperless\")."
  (mapcar (lambda (pair)
            (destructuring-bind (key . value) pair
              (if value
                  (format nil "~A=~A" key value)
                  (format nil "~A" key))))
          alist))

(defun txt-strings->alist (strings)
  "Inverse of TXT-ALIST->STRINGS: split each \"key=value\" on the first #\\=."
  (mapcar (lambda (s)
            (let ((eq (position #\= s)))
              (if eq
                  (cons (subseq s 0 eq) (subseq s (1+ eq)))
                  (cons s nil))))
          strings))

(defun address-record (name address ttl)
  "An A or AAAA record chosen by ADDRESS length (4 or 16 octets)."
  (ecase (length address)
    (4  (make-instance 'a-record    :name name :address address
                                    :ttl ttl :cache-flush t))
    (16 (make-instance 'aaaa-record :name name :address address
                                    :ttl ttl :cache-flush t))))

(defun address-types (addresses)
  "The address record types present in ADDRESSES: A for any 4-octet address,
AAAA for any 16-octet one."
  (let ((types '()))
    (when (some (lambda (a) (= 16 (length a))) addresses) (push +type-aaaa+ types))
    (when (some (lambda (a) (= 4  (length a))) addresses) (push +type-a+ types))
    types))

(defun service-info-records (info &key (host-ttl *default-host-ttl*)
                                       (other-ttl *default-other-ttl*))
  "Expand INFO into the list of records that advertise it.
Order: PTR, SRV, TXT, then one A/AAAA per address."
  (let ((instance (service-instance-name info)))
    (append
     (list
      ;; Shared PTR: type -> instance.  Not cache-flush (many instances share it).
      (make-instance 'ptr-record
                     :name (service-info-type info) :target instance
                     :ttl other-ttl)
      ;; Unique SRV: instance -> host:port.
      (make-instance 'srv-record
                     :name instance :cache-flush t :ttl host-ttl
                     :priority (service-info-priority info)
                     :weight (service-info-weight info)
                     :port (service-info-port info)
                     :target (service-info-host info))
      ;; Unique TXT.
      (make-instance 'txt-record
                     :name instance :cache-flush t :ttl other-ttl
                     :strings (txt-alist->strings (service-info-txt info))))
     ;; Unique address records.
     (mapcar (lambda (addr)
               (address-record (service-info-host info) addr host-ttl))
             (service-info-addresses info))
     ;; NSEC records assert exactly which types exist, so a listener won't wait
     ;; on absent ones (the classic case: no AAAA on an IPv4-only host).
     ;; RFC 6762 §6.1.  next-name is the record's own name; bitmap lists the
     ;; concrete data types present at that name.
     (list (make-instance 'nsec-record
                          :name instance :next-name instance
                          :cache-flush t :ttl host-ttl
                          :types (list +type-txt+ +type-srv+)))
     (let ((atypes (address-types (service-info-addresses info))))
       (when atypes
         (list (make-instance 'nsec-record
                              :name (service-info-host info)
                              :next-name (service-info-host info)
                              :cache-flush t :ttl host-ttl
                              :types atypes)))))))

;;; Reassembly (browser side): given the records seen for one instance, build a
;;; SERVICE-INFO.  Returns NIL if the essential SRV record is missing.
(defun service-info-from-records (type instance records)
  (let ((srv (find-if (lambda (r) (and (typep r 'srv-record)
                                       (string-equal (rr-name r) instance)))
                      records))
        (txt (find-if (lambda (r) (and (typep r 'txt-record)
                                       (string-equal (rr-name r) instance)))
                      records)))
    (when srv
      (let ((host (srv-target srv)))
        (make-service-info
         :type type
         :name (subseq instance 0 (max 0 (- (length instance) (length type) 1)))
         :host host
         :port (srv-port srv)
         :priority (srv-priority srv)
         :weight (srv-weight srv)
         :addresses (loop for r in records
                          when (and (or (typep r 'a-record) (typep r 'aaaa-record))
                                    (string-equal (rr-name r) host))
                            collect (if (typep r 'a-record)
                                        (a-address r) (aaaa-address r)))
         :txt (if txt (txt-strings->alist (txt-strings txt)) '()))))))
