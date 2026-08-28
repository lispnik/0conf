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

;;; --- reconciling sockets with the live interface list ----------------------
;;;
;;; The planner is pure, so a NIC appearing, vanishing, or changing address can
;;; be tested exactly — no network, no sockets, and none of the flakiness that
;;; poking at real interfaces would bring.

(defun fake-interface (name &key ipv4 has-v6 index)
  (0conf::make-net-interface :name name :ipv4 ipv4 :has-v6 has-v6 :index index))

(defun fake-socket (name family &key address index)
  "An MDNS-SOCKET record with no actual socket behind it — enough for the planner,
which only ever reads the interface identity."
  (0conf::%make-mdns-socket :socket nil :family family :interface-name name
                            :interface-address address :interface-index index))

(test interface-specs-cover-both-families
  "One IPv4 socket per addressed NIC, one IPv6 socket per v6-capable NIC."
  (let* ((ifaces (list (fake-interface "en0" :ipv4 #(192 168 1 5) :has-v6 t :index 4)
                       (fake-interface "en1" :ipv4 #(10 0 0 2))
                       (fake-interface "en2" :has-v6 t :index 6)))
         (specs (0conf::interface-socket-specs ifaces)))
    (is (= 4 (length specs)))
    (is (equal '(:ipv4 :ipv6 :ipv4 :ipv6) (mapcar #'first specs)))))

(test an-unchanged-interface-list-plans-no-work
  (let* ((ifaces (list (fake-interface "en0" :ipv4 #(192 168 1 5))))
         (sockets (list (fake-socket "en0" :ipv4 :address #(192 168 1 5)))))
    (multiple-value-bind (open close)
        (0conf::plan-socket-changes sockets (0conf::interface-socket-specs ifaces))
      (is (null open))
      (is (null close)))))

(test a-new-interface-is-planned-for-opening
  "The case that used to need a restart: a NIC that appears after startup."
  (let* ((ifaces (list (fake-interface "en0" :ipv4 #(192 168 1 5))
                       (fake-interface "en5" :ipv4 #(10 1 1 1))))
         (sockets (list (fake-socket "en0" :ipv4 :address #(192 168 1 5)))))
    (multiple-value-bind (open close)
        (0conf::plan-socket-changes sockets (0conf::interface-socket-specs ifaces))
      (is (= 1 (length open)))
      (is (string= "en5" (0conf::net-interface-name (second (first open)))))
      (is (null close)))))

(test a-vanished-interface-is-planned-for-closing
  (let* ((ifaces (list (fake-interface "en0" :ipv4 #(192 168 1 5))))
         (gone (fake-socket "utun3" :ipv4 :address #(100 64 0 1)))
         (sockets (list (fake-socket "en0" :ipv4 :address #(192 168 1 5)) gone)))
    (multiple-value-bind (open close)
        (0conf::plan-socket-changes sockets (0conf::interface-socket-specs ifaces))
      (is (null open))
      (is (equal (list gone) close)))))

(test a-new-address-on-the-same-nic-replaces-its-socket
  "A DHCP renewal keeps the NIC name but changes what IP_MULTICAST_IF must be
pinned to, so the old socket is retired and a new one opened."
  (let* ((ifaces (list (fake-interface "en0" :ipv4 #(192 168 1 77))))
         (old (fake-socket "en0" :ipv4 :address #(192 168 1 5)))
         (sockets (list old)))
    (multiple-value-bind (open close)
        (0conf::plan-socket-changes sockets (0conf::interface-socket-specs ifaces))
      (is (= 1 (length open)))
      (is (equalp #(192 168 1 77)
                  (0conf::net-interface-ipv4 (second (first open)))))
      (is (equal (list old) close)))))

(test the-ipv6-socket-of-a-nic-tracks-its-index
  "v6 sockets are keyed by interface index, not address."
  (let* ((ifaces (list (fake-interface "en0" :has-v6 t :index 9)))
         (stale (fake-socket "en0" :ipv6 :index 4)))
    (multiple-value-bind (open close)
        (0conf::plan-socket-changes (list stale) (0conf::interface-socket-specs ifaces))
      (is (= 1 (length open)))
      (is (equal (list stale) close)))))
