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

(test mdns-ipv6-socket-opens-and-closes
  "Exercises the AF_INET6 path: SO_REUSEPORT, IPV6_JOIN_GROUP(ff02::fb), and
IPV6_MULTICAST_HOPS.  Skips if the environment forbids it."
  (handler-case
      (let ((socket (make-mdns-socket :family :ipv6)))
        (unwind-protect
             (is (typep socket 'mdns-socket))
          (close-mdns-socket socket)))
    (error (e)
      (skip "IPv6 mDNS socket unavailable in this environment: ~A" e))))

;;; --- interface enumeration (getifaddrs) ------------------------------------

(test list-interfaces-enumerates-loopback
  "Validates the whole getifaddrs walk (struct offsets, family read, name copy)
without any multicast: loopback 127.0.0.1 must appear when not filtered out."
  (let ((ifaces (list-interfaces :include-loopback t :multicast-only nil)))
    (is (not (null ifaces)))
    (is (every #'net-interface-name ifaces))
    (is (find #(127 0 0 1) ifaces :key #'net-interface-ipv4 :test #'equalp))
    ;; if_nametoindex gives positive indices
    (is (every (lambda (i) (let ((x (net-interface-index i))) (or (null x) (plusp x))))
               ifaces))))

(test list-interfaces-filters-loopback-by-default
  (is (not (find #(127 0 0 1) (list-interfaces)
                 :key #'net-interface-ipv4 :test #'equalp))))

(test per-interface-socket-opens-and-closes
  "Opens a socket with the group joined on a specific interface (interface-scoped
IP_ADD_MEMBERSHIP + IP_MULTICAST_IF).  Skips if the environment forbids it."
  (handler-case
      (let ((iface (find-if #'net-interface-ipv4 (list-interfaces))))
        (if iface
            (let ((s (0conf::make-ipv4-mdns-socket-on iface)))
              (unwind-protect
                   (progn (is (typep s 'mdns-socket))
                          (is (equalp (net-interface-ipv4 iface)
                                      (0conf::mdns-socket-interface-address s))))
                (close-mdns-socket s)))
            (skip "no non-loopback IPv4 interface available")))
    (error (e) (skip "per-interface socket unavailable: ~A" e))))

(test open-interface-sockets-returns-sockets
  "The responder's socket-opening helper yields at least one socket (per-interface,
or the INADDR_ANY fallback).  Skips if the sandbox forbids binding 5353."
  (handler-case
      (let ((socks (0conf::open-interface-sockets)))
        (unwind-protect
             (progn (is (not (null socks)))
                    (is (every (lambda (s) (typep s 'mdns-socket)) socks)))
          (mapc #'close-mdns-socket socks)))
    (error (e) (skip "socket enumeration unavailable: ~A" e))))
