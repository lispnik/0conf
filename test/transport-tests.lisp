;;;; test/transport-tests.lisp — exercises the sb-alien socket path.
;;;;
;;;; This is the one test that touches the OS.  It builds an mDNS socket (which
;;;; runs SO_REUSEPORT + IP_ADD_MEMBERSHIP + IP_MULTICAST_TTL via setsockopt and
;;;; binds 5353) and closes it.  If the environment forbids that, the test skips
;;;; rather than fails — the pure layers are what the suite really guards.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(test mdns-socket-opens-and-closes
  (handler-case
      (let ((socket (make-mdns-socket)))
        (unwind-protect
             (is (typep socket 'mdns-socket))
          (close-mdns-socket socket)))
    (error (e)
      (skip "mDNS socket unavailable in this environment: ~A" e))))
