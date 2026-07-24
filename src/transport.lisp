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
  (defconstant +ipv6-join-group+     12)
  (defconstant +af-inet6+           30))     ; Darwin

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
  (defconstant +ipv6-join-group+     20)
  (defconstant +af-inet6+           10))     ; Linux

#-(or darwin linux)
(error "0conf transport: unsupported OS (need Darwin or Linux socket constants).")

;;; Interface enumeration constants (shared across Darwin/Linux).
(defconstant +af-inet+          2)
(defconstant +iff-up+           #x1)
(defconstant +iff-loopback+     #x8)
(defconstant +iff-pointopoint+  #x10)
(defconstant +iff-multicast+    #x8000)

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

(defun join-multicast-v4 (fd group-octets &optional (iface-octets #(0 0 0 0)))
  "IP_ADD_MEMBERSHIP for GROUP-OCTETS on the interface with address IFACE-OCTETS
(default INADDR_ANY = the system's default interface).
struct ip_mreq { in_addr imr_multiaddr; in_addr imr_interface; } — 8 bytes."
  (sb-alien:with-alien ((mreq (sb-alien:array (sb-alien:unsigned 8) 8)))
    (dotimes (i 4) (setf (sb-alien:deref mreq i) (aref group-octets i)))
    (dotimes (i 4) (setf (sb-alien:deref mreq (+ 4 i)) (aref iface-octets i)))
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

;;; --- interface enumeration (getifaddrs) ------------------------------------
;;;
;;; struct ifaddrs is laid out identically on Darwin arm64 and Linux (64-bit):
;;; next(ptr) name(ptr) flags(uint) <pad> addr(ptr) ...  We let SBCL compute the
;;; pad via define-alien-type.  The one platform-divergent part is the sockaddr
;;; header: Darwin has sa_len(1)+sa_family(1); Linux has sa_family(2).  The IPv4
;;; address always sits at sockaddr_in offset 4.

(sb-alien:define-alien-type nil
  (sb-alien:struct ifaddrs
    (ifa-next    (sb-alien:* (sb-alien:struct ifaddrs)))
    (ifa-name    sb-alien:c-string)
    (ifa-flags   sb-alien:unsigned-int)
    (ifa-addr    (sb-alien:* (sb-alien:unsigned 8)))
    (ifa-netmask (sb-alien:* (sb-alien:unsigned 8)))
    (ifa-dstaddr (sb-alien:* (sb-alien:unsigned 8)))
    (ifa-data    (sb-alien:* (sb-alien:unsigned 8)))))

(sb-alien:define-alien-routine ("getifaddrs" %getifaddrs) sb-alien:int
  (ifap (sb-alien:* (sb-alien:* (sb-alien:struct ifaddrs)))))

(sb-alien:define-alien-routine ("freeifaddrs" %freeifaddrs) sb-alien:void
  (ifa (sb-alien:* (sb-alien:struct ifaddrs))))

(sb-alien:define-alien-routine ("if_nametoindex" %if-nametoindex) sb-alien:unsigned-int
  (ifname sb-alien:c-string))

(defstruct net-interface
  name          ; interface name string, e.g. "en0"
  index         ; if_nametoindex value (for IPv6 joins), or NIL
  ipv4          ; a 4-octet vector, or NIL
  (has-v6 nil)) ; true if the interface has an IPv6 address

(defun sockaddr-family (sap)
  #+darwin (sb-sys:sap-ref-8 sap 1)      ; sa_len then sa_family
  #+linux  (sb-sys:sap-ref-16 sap 0))    ; sa_family (u16)

(defun list-interfaces (&key include-loopback (multicast-only t))
  "Enumerate usable network interfaces via getifaddrs(3).  Returns a list of
NET-INTERFACE (name, index, ipv4, has-v6).  Best-effort: returns NIL if
getifaddrs fails.  By default filters to up, multicast-capable, non-loopback
interfaces; pass :INCLUDE-LOOPBACK T / :MULTICAST-ONLY NIL to widen (used by
tests, since loopback is always present)."
  (sb-alien:with-alien ((head (sb-alien:* (sb-alien:struct ifaddrs))))
    (unless (zerop (%getifaddrs (sb-alien:addr head)))
      (return-from list-interfaces nil))
    (unwind-protect
         (let ((by-name (make-hash-table :test 'equal))
               (order '()))
           (flet ((entry (name)
                    (or (gethash name by-name)
                        (progn (push name order)
                               (setf (gethash name by-name)
                                     (make-net-interface :name name))))))
             (loop for node = head then (sb-alien:slot node 'ifa-next)
                   until (sb-alien:null-alien node)
                   do (let ((addr (sb-alien:slot node 'ifa-addr))
                            (flags (sb-alien:slot node 'ifa-flags))
                            (name (sb-alien:slot node 'ifa-name)))
                        (when (and (not (sb-alien:null-alien addr))
                                   (logtest flags +iff-up+)
                                   (or (not multicast-only) (logtest flags +iff-multicast+))
                                   ;; skip VPN/point-to-point tunnels for mDNS
                                   (or (not multicast-only)
                                       (not (logtest flags +iff-pointopoint+)))
                                   (or include-loopback (not (logtest flags +iff-loopback+))))
                          (let* ((sap (sb-alien:alien-sap addr))
                                 (family (sockaddr-family sap)))
                            (cond
                              ((= family +af-inet+)
                               (let ((e (entry name)))
                                 (unless (net-interface-ipv4 e)
                                   (setf (net-interface-ipv4 e)
                                         (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
                                           (dotimes (i 4)
                                             (setf (aref v i) (sb-sys:sap-ref-8 sap (+ 4 i))))
                                           v)))))
                              ((= family +af-inet6+)
                               (setf (net-interface-has-v6 (entry name)) t))))))))
           (loop for name in (nreverse order)
                 for e = (gethash name by-name)
                 do (let ((idx (%if-nametoindex name)))
                      (setf (net-interface-index e) (if (plusp idx) idx nil)))
                 collect e))
      (%freeifaddrs head))))

;;; --- the socket ------------------------------------------------------------

(defstruct (mdns-socket (:constructor %make-mdns-socket))
  socket
  (family :ipv4)
  (interface-name nil)      ; NIC name, or NIL for the INADDR_ANY fallback socket
  (interface-address nil)   ; IPv4 octets this socket egresses on, or NIL
  (interface-index nil))    ; IPv6 interface index, or NIL

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

;;; --- per-interface sockets (dual-stack, multi-homed) -----------------------

(defun make-ipv4-mdns-socket-on (iface &optional (port +mdns-port+))
  "An IPv4 mDNS socket bound to all interfaces but with the group joined on, and
egress pinned to, the interface IFACE (a NET-INTERFACE with an :ipv4 address)."
  (let* ((addr (net-interface-ipv4 iface))
         (sock (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
         (fd (sb-bsd-sockets:socket-file-descriptor sock)))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (sb-bsd-sockets:socket-close sock)))))
      (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
      (set-sockopt-int fd +sol-socket+ +so-reuseport+ 1)
      (sb-bsd-sockets:socket-bind sock #(0 0 0 0) port)
      (join-multicast-v4 fd (parse-ipv4 +mdns-group-v4+) addr)   ; join on this NIC
      (set-multicast-interface fd addr)                          ; egress on this NIC
      (set-sockopt-int fd +ipproto-ip+ +ip-multicast-ttl+ 255)
      (set-sockopt-int fd +ipproto-ip+ +ip-multicast-loop+ 1))
    (%make-mdns-socket :socket sock :family :ipv4
                       :interface-name (net-interface-name iface)
                       :interface-address addr)))

(defun make-ipv6-mdns-socket-on (iface &optional (port +mdns-port+))
  "An IPv6 mDNS socket with the group joined on interface index (net-interface-index IFACE)."
  (let* ((index (net-interface-index iface))
         (sock (make-instance 'sb-bsd-sockets:inet6-socket :type :datagram :protocol :udp))
         (fd (sb-bsd-sockets:socket-file-descriptor sock)))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (sb-bsd-sockets:socket-close sock)))))
      (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
      (set-sockopt-int fd +sol-socket+ +so-reuseport+ 1)
      (sb-bsd-sockets:socket-bind sock (make-array 16 :initial-element 0) port)
      (join-multicast-v6 fd (parse-ipv6 +mdns-group-v6+) (or index 0))
      (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-hops+ 255)
      (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-loop+ 1))
    (%make-mdns-socket :socket sock :family :ipv6
                       :interface-name (net-interface-name iface)
                       :interface-index index)))

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
