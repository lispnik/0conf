;;;; 0conf.lisp — top-level public API tying the layers together.

(in-package #:0conf)

(defun start (&key services)
  "Start an mDNS responder and register SERVICES (a list of SERVICE-INFO).
Returns the RESPONDER; pass it to STOP."
  (let ((responder (start-responder (make-responder))))
    (dolist (service services)
      (register-service responder service))
    responder))

(defun stop (responder)
  "Stop a RESPONDER started with START."
  (stop-responder responder))
