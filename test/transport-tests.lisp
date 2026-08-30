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

;;; --- ancillary data: the receiving interface index -------------------------
;;;
;;; These build control buffers by hand, in both the Darwin and the Linux
;;; cmsghdr shape, so the walk is tested for both platforms wherever the suite
;;; runs — the alternative is that half of it is only ever exercised on the
;;; machine that happens to run CI.

(defun put-native-uint (octets offset size value)
  (dotimes (i size)
    (setf (aref octets (+ offset i)) (ldb (byte 8 (* 8 i)) value)))
  octets)

(defun build-cmsg (layout level type payload &key len)
  "One control message in LAYOUT's shape: header, then PAYLOAD at offset 16,
padded out to the 8-octet boundary.  LEN overrides the length field, for the
malformed cases."
  (let* ((real-len (+ 0conf::+cmsg-data-offset+ (length payload)))
         (total (0conf::cmsg-align real-len))
         (buffer (make-array total :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
    (put-native-uint buffer 0 (0conf::cmsg-layout-len-size layout) (or len real-len))
    (put-native-uint buffer (0conf::cmsg-layout-level-offset layout) 4 level)
    (put-native-uint buffer (0conf::cmsg-layout-type-offset layout) 4 type)
    (replace buffer payload :start1 0conf::+cmsg-data-offset+)
    buffer))

(defun in-pktinfo (ifindex)
  "struct in_pktinfo: ipi_ifindex first, then two in_addrs."
  (put-native-uint (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
                   0 4 ifindex))

(defun in6-pktinfo (ifindex)
  "struct in6_pktinfo: the 16-octet address, then ipi6_ifindex."
  (put-native-uint (make-array 20 :element-type '(unsigned-byte 8) :initial-element 0)
                   16 4 ifindex))

(defun cat-octets (&rest buffers)
  (apply #'concatenate '(vector (unsigned-byte 8)) buffers))

(test ipv4-pktinfo-yields-the-interface-index
  "Both layouts, since the machine running the suite only has one of them."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+ipproto-ip+
                               (0conf::cmsg-layout-ip-type layout)
                               (in-pktinfo 11))))
      (is (eql 11 (0conf::control-interface-index control (length control) layout))))))

(test ipv6-pktinfo-yields-the-interface-index
  "The v6 index sits after the address, not at the start of the payload."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+ipproto-ipv6+
                               (0conf::cmsg-layout-ipv6-type layout)
                               (in6-pktinfo 9))))
      (is (eql 9 (0conf::control-interface-index control (length control) layout))))))

(test the-index-is-found-past-an-unrelated-control-message
  "The kernel may attach more than one; the walk must step over the others."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (cat-octets
                    (build-cmsg layout 0conf::+sol-socket+ 2 (in-pktinfo 77))
                    (build-cmsg layout 0conf::+ipproto-ip+
                                (0conf::cmsg-layout-ip-type layout)
                                (in-pktinfo 4)))))
      (is (eql 4 (0conf::control-interface-index control (length control) layout))))))

(test no-pktinfo-means-no-index
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+sol-socket+ 2 (in-pktinfo 5))))
      (is (null (0conf::control-interface-index control (length control) layout))))))

(test an-empty-control-buffer-yields-no-index
  (is (null (0conf::control-interface-index
             (make-array 0 :element-type '(unsigned-byte 8)))))
  ;; A buffer too short to hold even one header must not be read past.
  (is (null (0conf::control-interface-index
             (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))))

(test a-control-message-running-past-the-buffer-is-refused
  "A length field claiming more than was delivered must end the walk, not read
off the end of the buffer."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+ipproto-ip+
                               (0conf::cmsg-layout-ip-type layout)
                               (in-pktinfo 11) :len 4096)))
      (is (null (0conf::control-interface-index control (length control) layout))))))

(test a-degenerate-length-cannot-hang-the-walk
  "A cmsg_len below the header size would advance the cursor by nothing and spin
forever; it has to terminate the walk instead.  If this test hangs, it fails."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (dolist (bogus '(0 1 15))
      (let ((control (cat-octets
                      (build-cmsg layout 0conf::+sol-socket+ 2 (in-pktinfo 1)
                                  :len bogus)
                      (build-cmsg layout 0conf::+ipproto-ip+
                                  (0conf::cmsg-layout-ip-type layout)
                                  (in-pktinfo 12)))))
        (is (null (0conf::control-interface-index control (length control) layout)))))))

(test the-declared-length-bounds-the-walk-not-the-buffer-size
  "recvmsg reports how much control data it actually wrote; octets past that are
stale and must not be parsed."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+ipproto-ip+
                               (0conf::cmsg-layout-ip-type layout)
                               (in-pktinfo 11))))
      (is (eql 11 (0conf::control-interface-index control (length control) layout)))
      (is (null (0conf::control-interface-index control 0 layout))))))

(test an-unspecified-index-reads-as-absent
  "Index 0 means 'the kernel did not say'.  Darwin reports it for looped-back
traffic, and it must not be handed on as if it named a link."
  (dolist (layout (list 0conf::*darwin-cmsg-layout* 0conf::*linux-cmsg-layout*))
    (let ((control (build-cmsg layout 0conf::+ipproto-ip+
                               (0conf::cmsg-layout-ip-type layout)
                               (in-pktinfo 0))))
      (is (null (0conf::control-interface-index control (length control) layout))))
    ;; ... and a real index later in the buffer is still found.
    (let ((control (cat-octets
                    (build-cmsg layout 0conf::+ipproto-ip+
                                (0conf::cmsg-layout-ip-type layout) (in-pktinfo 0))
                    (build-cmsg layout 0conf::+ipproto-ipv6+
                                (0conf::cmsg-layout-ipv6-type layout) (in6-pktinfo 7)))))
      (is (eql 7 (0conf::control-interface-index control (length control) layout))))))

;;; --- the peer address recvmsg hands back -----------------------------------

(defun build-sockaddr-in (dotted port)
  "A sockaddr_in in this platform's shape: the port is network order, the family
field is where SOCKADDR-OCTETS-FAMILY expects it."
  (let ((b (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    #+darwin (setf (aref b 0) 16 (aref b 1) 0conf::+af-inet+)
    #+linux  (put-native-uint b 0 2 0conf::+af-inet+)
    (setf (aref b 2) (ldb (byte 8 8) port)
          (aref b 3) (ldb (byte 8 0) port))
    (replace b (parse-ipv4 dotted) :start1 4)
    b))

(defun build-sockaddr-in6 (address port)
  (let ((b (make-array 28 :element-type '(unsigned-byte 8) :initial-element 0)))
    #+darwin (setf (aref b 0) 28 (aref b 1) 0conf::+af-inet6+)
    #+linux  (put-native-uint b 0 2 0conf::+af-inet6+)
    (setf (aref b 2) (ldb (byte 8 8) port)
          (aref b 3) (ldb (byte 8 0) port))
    (replace b (parse-ipv6 address) :start1 8)
    b))

(test a-v4-peer-sockaddr-decodes-to-host-and-port
  (multiple-value-bind (host port)
      (0conf::parse-sockaddr-peer (build-sockaddr-in "192.168.1.42" 5353))
    (is (string= "192.168.1.42" host))
    (is (eql 5353 port))))

(test a-v6-peer-sockaddr-decodes-past-the-flowinfo
  "The v6 address starts at offset 8, not 4 — flowinfo sits in between.
Compared as an address rather than as text: FORMAT-IPV6 writes every group out
(\"fe80:0:0:0:0:0:0:1\"), and this test is about the offset, not the spelling."
  (multiple-value-bind (host port)
      (0conf::parse-sockaddr-peer (build-sockaddr-in6 "fe80::1" 5353))
    (is (equalp (parse-ipv6 "fe80::1") (parse-ipv6 host)))
    (is (eql 5353 port))))

(test a-high-port-survives-the-network-order-read
  "A port above 32767 must not come back sign-flipped or byte-swapped."
  (is (eql 61244 (nth-value 1 (0conf::parse-sockaddr-peer
                               (build-sockaddr-in "127.0.0.1" 61244))))))

(test a-truncated-or-unknown-sockaddr-yields-nothing
  (is (null (0conf::parse-sockaddr-peer
             (make-array 0 :element-type '(unsigned-byte 8)))))
  (is (null (0conf::parse-sockaddr-peer
             (subseq (build-sockaddr-in "10.0.0.1" 5353) 0 6))))
  ;; An address family we do not speak (AF_UNIX and the like).
  (let ((b (build-sockaddr-in "10.0.0.1" 5353)))
    #+darwin (setf (aref b 1) 99)
    #+linux  (put-native-uint b 0 2 99)
    (is (null (0conf::parse-sockaddr-peer b)))))

;;; --- the socket-count cap --------------------------------------------------

(test the-socket-cap-holds-the-spec-list-down
  (let ((0conf::*capped-interface-count* nil)
        (ifaces (loop for i from 1 to 10
                      collect (fake-interface (format nil "en~D" i)
                                              :ipv4 (vector 10 0 0 i) :has-v6 t
                                              :index i))))
    (is (= 20 (length (0conf::interface-socket-specs ifaces))))
    (is (= 20 (length (handler-bind ((warning #'muffle-warning))
                        (0conf::usable-socket-specs ifaces 20)))))
    (is (= 6 (length (handler-bind ((warning #'muffle-warning))
                       (0conf::usable-socket-specs ifaces 6)))))
    ;; Under the cap nothing is dropped and nothing is warned about.
    (is (= 20 (length (0conf::usable-socket-specs ifaces 99))))))

(test going-over-the-cap-is-reported-once
  "A silent cap looks like interfaces mysteriously not working; a cap that warns
every five seconds is worse."
  (let* ((0conf::*capped-interface-count* nil)
         (ifaces (loop for i from 1 to 5
                       collect (fake-interface (format nil "en~D" i)
                                               :ipv4 (vector 10 0 0 i) :index i)))
         (warnings 0))
    (handler-bind ((warning (lambda (w) (declare (ignore w))
                              (incf warnings) (muffle-warning))))
      (0conf::usable-socket-specs ifaces 2)
      (0conf::usable-socket-specs ifaces 2)
      (0conf::usable-socket-specs ifaces 2))
    (is (= 1 warnings))))

(test only-a-failed-syscall-falls-back-to-the-blocking-receive
  "RECVMSG-UNAVAILABLE is signalled just for the syscall.  A decoding error
happens after the datagram has been consumed, and the fallback is a blocking
read with no timeout — taking it there would park the listener until some
unrelated packet turned up."
  (is (subtypep '0conf::recvmsg-unavailable 'error))
  ;; The syscall's own condition is what the fallback handler catches ...
  (is (eq :fell-back (handler-case (error '0conf::recvmsg-unavailable :fd 7)
                       (0conf::recvmsg-unavailable () :fell-back))))
  ;; ... and an ordinary decoding error escapes it, reaching the listener, which
  ;; drops the packet and carries on instead of parking on a blocking read.
  (is-true (nth-value 1 (ignore-errors
                         (handler-case (error "decode")
                           (0conf::recvmsg-unavailable () :fell-back))))))
