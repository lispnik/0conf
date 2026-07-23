;;;; browser.lisp — DNS-SD discovery side (RFC 6763).
;;;;
;;;; BROWSE-ONCE is the simple synchronous workhorse: send a PTR query for a
;;;; service type, gather responses for a short window, then reassemble each
;;;; instance by following PTR -> SRV -> TXT -> A/AAAA out of a scratch cache.
;;;; BROWSE runs that on a background thread and calls back per instance.

(in-package #:0conf)

(defun all-address-records (cache instance)
  "A/AAAA records for the host named by INSTANCE's SRV record."
  (let ((srv (first (cache-get cache instance +type-srv+))))
    (when srv
      (append (cache-get cache (srv-target srv) +type-a+)
              (cache-get cache (srv-target srv) +type-aaaa+)))))

(defun assemble-services (cache type)
  (let ((instances (remove-duplicates
                    (loop for r in (cache-get cache type +type-ptr+)
                          collect (ptr-target r))
                    :test #'string-equal)))
    (loop for instance in instances
          for records = (append (cache-get cache instance +type-srv+)
                                (cache-get cache instance +type-txt+)
                                (all-address-records cache instance))
          for info = (service-info-from-records type instance records)
          when info collect info)))

(defun browse-once (type &key (timeout 2.0) interface)
  "Query for service TYPE (e.g. \"_ipp._tcp.local\"), collect responses for
TIMEOUT seconds, and return a list of SERVICE-INFO.  INTERFACE (a dotted IPv4
string) picks the multicast egress interface — needed on VPN/multi-homed hosts."
  (let ((socket (make-mdns-socket :interface interface))
        (cache (make-cache)))
    (unwind-protect
         (progn
           (mdns-send socket
                      (encode-message
                       (make-dns-message
                        :questions (list (make-question :name type
                                                        :qtype +type-ptr+)))))
           (let ((deadline (+ (get-internal-real-time)
                              (round (* timeout internal-time-units-per-second)))))
             (loop for remaining = (/ (- deadline (get-internal-real-time))
                                      internal-time-units-per-second)
                   while (plusp remaining)
                   do (let ((octets (mdns-recv-timeout socket (float remaining 1.0))))
                        (when octets
                          (let ((message (decode-message octets)))
                            (dolist (r (append (dns-message-answers message)
                                               (dns-message-additionals message)))
                              (cache-add cache r)))))))
           (assemble-services cache type))
      (close-mdns-socket socket))))

(defun browse (type callback &key (timeout 2.0) interface)
  "Browse for TYPE on a background thread, calling (funcall CALLBACK service-info)
for each instance found.  Returns the thread."
  (bordeaux-threads:make-thread
   (lambda ()
     (dolist (info (browse-once type :timeout timeout :interface interface))
       (funcall callback info)))
   :name "0conf-browse"))
