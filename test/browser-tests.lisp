;;;; test/browser-tests.lisp — the ServiceBrowser diff/notify logic.
;;;;
;;;; DIFF-AND-NOTIFY only reads the responder's cache, so these drive it with a
;;;; pre-populated cache (no socket, no threads) and check the callbacks.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defparameter *browser-service*
  (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                     :port 1 :addresses (list (parse-ipv4 "10.0.0.1"))))

(defun seed-cache (responder info)
  (dolist (r (service-info-records info))
    (cache-add (0conf::responder-cache responder) r)))

(defun make-browser (responder &key on-add on-update on-remove)
  (0conf::%make-service-browser :responder responder :type "_x._tcp.local"
                                :on-add on-add :on-update on-update
                                :on-remove on-remove))

(test browser-fires-add-once
  (let* ((r (make-responder))
         (added '())
         (b (make-browser r :on-add (lambda (i) (push i added)))))
    (seed-cache r *browser-service*)
    (0conf::diff-and-notify b)
    (is (= 1 (length added)))
    (is (string= "N" (service-info-name (first added))))
    ;; a second diff with no change fires nothing more
    (0conf::diff-and-notify b)
    (is (= 1 (length added)))))

(test browser-fires-update-on-change
  (let* ((r (make-responder))
         (updated '())
         (b (make-browser r :on-update (lambda (i) (push i updated)))))
    (seed-cache r *browser-service*)          ; real port is 1
    ;; seed KNOWN with a stale copy (different port) so the diff sees a change
    (setf (gethash (service-instance-name *browser-service*)
                   (0conf::service-browser-known b))
          (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                             :port 999 :addresses (list (parse-ipv4 "10.0.0.1"))))
    (0conf::diff-and-notify b)
    (is (= 1 (length updated)))
    (is (= 1 (service-info-port (first updated))))))   ; reports the current port

(test browser-fires-remove-on-goodbye
  (let* ((r (make-responder))
         (removed '())
         (b (make-browser r :on-remove (lambda (name) (push name removed)))))
    (seed-cache r *browser-service*)
    (0conf::diff-and-notify b)                 ; establishes the instance as known
    ;; goodbye the SRV (ttl 0) -> instance can no longer be assembled
    (let ((srv (find-if (lambda (x) (typep x 'srv-record))
                        (service-info-records *browser-service*))))
      (setf (rr-ttl srv) 0)
      (cache-add (0conf::responder-cache r) srv))
    (0conf::diff-and-notify b)
    (is (equal (list "N._x._tcp.local") removed))))

(test service-info-equal-detects-differences
  (let ((base *browser-service*))
    (is (0conf::service-info-equal
         base (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                 :port 1 :addresses (list (parse-ipv4 "10.0.0.1")))))
    ;; different port
    (is (not (0conf::service-info-equal
              base (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                      :port 2 :addresses (list (parse-ipv4 "10.0.0.1"))))))
    ;; different address
    (is (not (0conf::service-info-equal
              base (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                      :port 1 :addresses (list (parse-ipv4 "10.0.0.2"))))))))
