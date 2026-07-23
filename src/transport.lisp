;;;; transport.lisp — multicast UDP transport (SBCL: sb-bsd-sockets + sb-alien).
;;;;
;;;; This is the ONLY platform-specific file; everything else in 0conf is pure
;;;; and testable without a network.  sb-bsd-sockets gives us the socket and
;;;; SO_REUSEADDR, but NOT multicast-group join or SO_REUSEPORT, so those go
;;;; through a small setsockopt() shim kept entirely inside this file.
;;;;
;;;; IPv4 is implemented.  IPv6 (join ff02::fb on an AF_INET6 socket via
;;;; IPV6_JOIN_GROUP with an ipv6_mreq) is a documented stub — MAKE-MDNS-SOCKET
;;;; already dispatches on :FAMILY so it drops in beside the v4 path.

(in-package #:0conf)

;;; --- OS-specific socket-option numbers -------------------------------------

#+darwin
(progn
  (defconstant +sol-socket+        #xffff)
  (defconstant +so-reuseport+      #x0200)
  (defconstant +ipproto-ip+        0)
  (defconstant +ip-multicast-if+   9)
  (defconstant +ip-multicast-ttl+  10)
  (defconstant +ip-multicast-loop+ 11)
  (defconstant +ip-add-membership+ 12)
  (defconstant +ipproto-ipv6+       41)
  (defconstant +ipv6-multicast-hops+ 10)
  (defconstant +ipv6-multicast-loop+ 11)
  (defconstant +ipv6-join-group+     12))

#+linux
(progn
  (defconstant +sol-socket+        1)
  (defconstant +so-reuseport+      15)
  (defconstant +ipproto-ip+        0)
  (defconstant +ip-multicast-if+   32)
  (defconstant +ip-multicast-ttl+  33)
  (defconstant +ip-multicast-loop+ 34)
  (defconstant +ip-add-membership+ 35)
  (defconstant +ipproto-ipv6+       41)
  (defconstant +ipv6-multicast-hops+ 18)
  (defconstant +ipv6-multicast-loop+ 19)
  (defconstant +ipv6-join-group+     20))

#-(or darwin linux)
(error "0conf transport: unsupported OS (need Darwin or Linux socket constants).")

;;; --- setsockopt() shim -----------------------------------------------------

(sb-alien:define-alien-routine ("setsockopt" %setsockopt) sb-alien:int
  (fd      sb-alien:int)
  (level   sb-alien:int)
  (optname sb-alien:int)
  (optval  (sb-alien:* (sb-alien:unsigned 8)))
  (optlen  sb-alien:unsigned-int))

(defun set-sockopt-int (fd level optname value)
  (sb-alien:with-alien ((v sb-alien:int value))
    (let ((rc (%setsockopt fd level optname
                           (sb-alien:cast (sb-alien:addr v) (sb-alien:* (sb-alien:unsigned 8)))
                           4)))
      (when (minusp rc)
        (error "setsockopt(level=~D opt=~D val=~D) failed" level optname value)))))

(defun join-multicast-v4 (fd group-octets)
  "IP_ADD_MEMBERSHIP for GROUP-OCTETS on the default interface (INADDR_ANY).
struct ip_mreq { in_addr imr_multiaddr; in_addr imr_interface; } — 8 bytes."
  (sb-alien:with-alien ((mreq (sb-alien:array (sb-alien:unsigned 8) 8)))
    (dotimes (i 4) (setf (sb-alien:deref mreq i) (aref group-octets i)))
    (dotimes (i 4) (setf (sb-alien:deref mreq (+ 4 i)) 0))   ; INADDR_ANY
    (let ((rc (%setsockopt fd +ipproto-ip+ +ip-add-membership+
                           (sb-alien:addr (sb-alien:deref mreq 0))
                           8)))
      (when (minusp rc)
        (error "IP_ADD_MEMBERSHIP for ~A failed" (format-ipv4 group-octets))))))

(defun join-multicast-v6 (fd group-octets ifindex)
  "IPV6_JOIN_GROUP for GROUP-OCTETS on interface index IFINDEX (0 = default).
struct ipv6_mreq { in6_addr ipv6mr_multiaddr (16); unsigned int ipv6mr_interface (4) }
— 20 bytes.  The interface index is a native unsigned int (host byte order)."
  (sb-alien:with-alien ((mreq (sb-alien:array (sb-alien:unsigned 8) 20)))
    (dotimes (i 16) (setf (sb-alien:deref mreq i) (aref group-octets i)))
    (setf (sb-alien:deref mreq 16) (ldb (byte 8 0) ifindex)
          (sb-alien:deref mreq 17) (ldb (byte 8 8) ifindex)
          (sb-alien:deref mreq 18) (ldb (byte 8 16) ifindex)
          (sb-alien:deref mreq 19) (ldb (byte 8 24) ifindex))
    (let ((rc (%setsockopt fd +ipproto-ipv6+ +ipv6-join-group+
                           (sb-alien:addr (sb-alien:deref mreq 0))
                           20)))
      (when (minusp rc)
        (error "IPV6_JOIN_GROUP for ~A failed" (format-ipv6 group-octets))))))

(defun set-multicast-interface (fd iface-octets)
  "IP_MULTICAST_IF: choose the egress interface for multicast sends by its IPv4
address.  Essential on multi-homed / VPN hosts where the default route points at
a tunnel that carries no multicast — the exact situation on this dev machine."
  (sb-alien:with-alien ((addr (sb-alien:array (sb-alien:unsigned 8) 4)))
    (dotimes (i 4) (setf (sb-alien:deref addr i) (aref iface-octets i)))
    (let ((rc (%setsockopt fd +ipproto-ip+ +ip-multicast-if+
                           (sb-alien:addr (sb-alien:deref addr 0)) 4)))
      (when (minusp rc)
        (error "IP_MULTICAST_IF ~A failed" (format-ipv4 iface-octets))))))

;;; --- the socket ------------------------------------------------------------

(defstruct (mdns-socket (:constructor %make-mdns-socket))
  socket
  (family :ipv4))

(defun make-mdns-socket (&key (family :ipv4) (multicast t) (port +mdns-port+)
                              interface)
  "Open an mDNS UDP socket bound to PORT (5353), joined to the mDNS group.
FAMILY is :IPV4 or :IPV6.  For :IPV4, INTERFACE is a dotted-quad string selecting
the multicast egress interface (IP_MULTICAST_IF); for :IPV6 it is an interface
*index* (integer) for the group join (0 = default).

NOTE: on macOS 15+ sending/receiving multicast requires the
`com.apple.developer.networking.multicast` entitlement (and a signed binary);
an unentitled process gets EHOSTUNREACH on send regardless of routing."
  (ecase family
    (:ipv4 (make-ipv4-mdns-socket multicast port interface))
    (:ipv6 (make-ipv6-mdns-socket multicast port interface))))

(defun make-ipv4-mdns-socket (multicast port interface)
  (let* ((sock (make-instance 'sb-bsd-sockets:inet-socket
                              :type :datagram :protocol :udp))
         (fd (sb-bsd-sockets:socket-file-descriptor sock)))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (sb-bsd-sockets:socket-close sock)))))
      ;; Both are needed before bind: on macOS the system mDNSResponder already
      ;; holds 5353, so without SO_REUSEPORT the bind() fails outright.
      (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
      (set-sockopt-int fd +sol-socket+ +so-reuseport+ 1)
      (sb-bsd-sockets:socket-bind sock #(0 0 0 0) port)
      (when multicast
        (join-multicast-v4 fd (parse-ipv4 +mdns-group-v4+))
        (when interface
          (set-multicast-interface fd (parse-ipv4 interface)))
        (set-sockopt-int fd +ipproto-ip+ +ip-multicast-ttl+ 255)   ; RFC 6762 §11
        (set-sockopt-int fd +ipproto-ip+ +ip-multicast-loop+ 1)))
    (%make-mdns-socket :socket sock :family :ipv4)))

(defun make-ipv6-mdns-socket (multicast port interface)
  (let* ((sock (make-instance 'sb-bsd-sockets:inet6-socket
                              :type :datagram :protocol :udp))
         (fd (sb-bsd-sockets:socket-file-descriptor sock)))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (sb-bsd-sockets:socket-close sock)))))
      (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
      (set-sockopt-int fd +sol-socket+ +so-reuseport+ 1)
      (sb-bsd-sockets:socket-bind sock (make-array 16 :initial-element 0) port)
      (when multicast
        (join-multicast-v6 fd (parse-ipv6 +mdns-group-v6+) (or interface 0))
        (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-hops+ 255)   ; RFC 6762 §11
        (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-loop+ 1)))
    (%make-mdns-socket :socket sock :family :ipv6)))

(defun close-mdns-socket (mdns)
  (ignore-errors (sb-bsd-sockets:socket-close (mdns-socket-socket mdns))))

;;; --- send / receive --------------------------------------------------------

(defun mdns-send (mdns octets &key host (port +mdns-port+))
  "Send OCTETS to HOST:PORT.  HOST defaults to the mDNS group for the socket's
address family; it is parsed as IPv4 or IPv6 to match."
  (let* ((family (mdns-socket-family mdns))
         (host (or host (ecase family
                          (:ipv4 +mdns-group-v4+)
                          (:ipv6 +mdns-group-v6+))))
         (addr (ecase family
                 (:ipv4 (parse-ipv4 host))
                 (:ipv6 (parse-ipv6 host)))))
    (sb-bsd-sockets:socket-send (mdns-socket-socket mdns)
                                octets (length octets)
                                :address (list addr port))))

(defun host->string (host)
  "Normalise the peer address socket-receive hands back into a string."
  (cond ((and (vectorp host) (= 4 (length host)))  (format-ipv4 host))
        ((and (vectorp host) (= 16 (length host))) (format-ipv6 host))
        (t (princ-to-string host))))

(defun mdns-recv (mdns &key (max 9000))
  "Block for one datagram.  Returns (values octets peer-host peer-port)."
  (multiple-value-bind (buffer size host port)
      (sb-bsd-sockets:socket-receive (mdns-socket-socket mdns)
                                     (make-array max :element-type '(unsigned-byte 8))
                                     max)
    (values (subseq buffer 0 size) (host->string host) port)))

(defun mdns-recv-timeout (mdns seconds)
  "Like MDNS-RECV but returns NIL if nothing arrives within SECONDS."
  (let ((fd (sb-bsd-sockets:socket-file-descriptor (mdns-socket-socket mdns))))
    (when (sb-sys:wait-until-fd-usable fd :input seconds)
      (mdns-recv mdns))))
