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

(defun browse-once (type &key (timeout 2.0) interface socket)
  "Query for service TYPE (e.g. \"_ipp._tcp.local\"), collect responses for
TIMEOUT seconds, and return a list of SERVICE-INFO.  INTERFACE (a dotted IPv4
string) picks the multicast egress interface — needed on VPN/multi-homed hosts.
SOCKET, if given, is used instead of opening one (and is left open) — for tests."
  (let* ((own-socket (null socket))
         (socket (or socket (make-mdns-socket :interface interface)))
         (cache (make-cache)))
    (unwind-protect
         (progn
           ;; A send failure on one interface (e.g. EHOSTUNREACH on a VPN link)
           ;; must not abort collection.
           (ignore-errors
             (mdns-send socket
                        (encode-message
                         (make-dns-message
                          :questions (list (make-question :name type
                                                          :qtype +type-ptr+))))))
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
      (when own-socket (close-mdns-socket socket)))))

(defun browse (type callback &key (timeout 2.0) interface)
  "Browse for TYPE on a background thread, calling (funcall CALLBACK service-info)
for each instance found.  Returns the thread."
  (bordeaux-threads:make-thread
   (lambda ()
     (dolist (info (browse-once type :timeout timeout :interface interface))
       (funcall callback info)))
   :name "0conf-browse"))

;;; ---------------------------------------------------------------------------
;;; Live async ServiceBrowser
;;;
;;; Attaches to a running RESPONDER (reusing its listener + cache), keeps a live
;;; picture of one service type, and fires callbacks as instances appear, change,
;;; and vanish.  Discovery uses a backing-off PTR query (RFC 6762 §5.2); the
;;; current set is recomputed from the cache on a short poll and diffed against
;;; what we last reported.  Removals come "for free": the cache filters expired
;;; records and treats a ttl-0 goodbye as deletion, so a vanished instance simply
;;; stops appearing in the diff.
;;; ---------------------------------------------------------------------------

(defstruct (service-browser (:constructor %make-service-browser))
  responder
  type
  on-add on-update on-remove
  (known (make-hash-table :test 'equal))   ; instance-name -> last service-info
  (thread nil)
  (running nil)
  (query-interval 1))                       ; current backoff, seconds

(defun address-set-equal (as bs)
  (and (= (length as) (length bs))
       (every (lambda (a) (find a bs :test #'equalp)) as)))

(defun txt-equal (a b)
  (equal (sort (copy-alist a) #'string< :key #'car)
         (sort (copy-alist b) #'string< :key #'car)))

(defun service-info-equal (a b)
  "Do two SERVICE-INFOs describe the same instance state (host/port/txt/addrs)?"
  (and (string-equal (service-info-host a) (service-info-host b))
       (= (service-info-port a) (service-info-port b))
       (txt-equal (service-info-txt a) (service-info-txt b))
       (address-set-equal (service-info-addresses a) (service-info-addresses b))))

(defun fire (callback arg)
  (when callback (ignore-errors (funcall callback arg))))

(defun send-browse-query (browser)
  "Send the PTR query, including the PTR answers we already know so responders
that would only repeat them stay quiet (known-answer suppression)."
  (let* ((responder (service-browser-responder browser))
         (type (service-browser-type browser))
         (known (bordeaux-threads:with-lock-held ((responder-lock responder))
                  (cache-get (responder-cache responder) type +type-ptr+))))
    (broadcast responder
               (encode-message
                (make-dns-message
                 :questions (list (make-question :name type :qtype +type-ptr+))
                 :answers known)))))

(defun diff-and-notify (browser)
  "Recompute the live instance set from the cache and fire add/update/remove."
  (let* ((responder (service-browser-responder browser))
         (type (service-browser-type browser))
         (current (bordeaux-threads:with-lock-held ((responder-lock responder))
                    (assemble-services (responder-cache responder) type)))
         (known (service-browser-known browser))
         (seen (make-hash-table :test 'equal)))
    (dolist (info current)
      (let* ((name (service-instance-name info))
             (prev (gethash name known)))
        (setf (gethash name seen) t)
        (cond
          ((null prev)
           (setf (gethash name known) info)
           (fire (service-browser-on-add browser) info))
          ((not (service-info-equal prev info))
           (setf (gethash name known) info)
           (fire (service-browser-on-update browser) info)))))
    (let ((gone '()))
      (maphash (lambda (name info)
                 (declare (ignore info))
                 (unless (gethash name seen) (push name gone)))
               known)
      (dolist (name gone)
        (remhash name known)
        (fire (service-browser-on-remove browser) name)))))

(defun browser-should-query-p (browser now next-query)
  "Time to send a query?  Either the backoff timer is due, or a cached record has
passed 80% of its lifetime and needs refreshing (RFC 6762 §5.2)."
  (or (>= now next-query)
      (let ((responder (service-browser-responder browser)))
        (bordeaux-threads:with-lock-held ((responder-lock responder))
          (cache-needs-refresh-p (responder-cache responder))))))

(defun browser-loop (browser poll)
  (let ((next-query 0))
    (loop while (service-browser-running browser) do
      (when (browser-should-query-p browser (get-internal-real-time) next-query)
        (ignore-errors (send-browse-query browser))
        (setf next-query (+ (get-internal-real-time)
                            (* (service-browser-query-interval browser)
                               internal-time-units-per-second))
              (service-browser-query-interval browser)
              (min 3600 (* 2 (service-browser-query-interval browser)))))
      (diff-and-notify browser)
      (sleep poll))))

(defun browse-services (responder type &key on-add on-update on-remove (poll 1.0))
  "Start a live browser for service TYPE on a running RESPONDER.  Calls
ON-ADD / ON-UPDATE with a SERVICE-INFO, and ON-REMOVE with the instance name, as
instances appear, change, and disappear.  Returns a SERVICE-BROWSER; stop it with
STOP-BROWSE."
  (let ((browser (%make-service-browser
                  :responder responder :type type
                  :on-add on-add :on-update on-update :on-remove on-remove)))
    (setf (service-browser-running browser) t
          (service-browser-thread browser)
          (bordeaux-threads:make-thread (lambda () (browser-loop browser poll))
                                        :name "0conf-browser"))
    browser))

(defun stop-browse (browser)
  (setf (service-browser-running browser) nil)
  (let ((thread (service-browser-thread browser)))
    (when (and thread (bordeaux-threads:thread-alive-p thread))
      (ignore-errors (bordeaux-threads:join-thread thread))))
  browser)
