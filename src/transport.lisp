;;;; transport.lisp — multicast UDP transport (SBCL: sb-bsd-sockets + sb-alien).
;;;;
;;;; This is the ONLY platform-specific file; everything else in 0conf is pure
;;;; and testable without a network.  sb-bsd-sockets gives us the socket and
;;;; SO_REUSEADDR, but NOT multicast-group join or SO_REUSEPORT, so those go
;;;; through a small setsockopt() shim kept entirely inside this file.
;;;;
;;;; Both families are implemented: MAKE-MDNS-SOCKET dispatches on :FAMILY, and
;;;; the v6 path joins ff02::fb with IPV6_JOIN_GROUP on a given interface index.
;;;;
;;;; Two things here are native-struct work rather than plain socket options:
;;;; walking getifaddrs() to enumerate interfaces, and reading the ancillary data
;;;; recvmsg() attaches to a datagram to learn which interface it arrived on.
;;;; Both have layouts that differ between Darwin and Linux; in each case the
;;;; parsing is split out as a pure function over octets so it can be tested for
;;;; both platforms on either one.

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
  (defconstant +af-inet6+           30)      ; Darwin
  ;; Receive-side interface attribution.  Darwin defines IP_RECVPKTINFO as
  ;; IP_PKTINFO (26), and delivers the same struct in_pktinfo Linux does, so the
  ;; option number differs but the payload does not.
  (defconstant +ip-recv-pktinfo+     26)
  (defconstant +ip-pktinfo-cmsg+     26)
  (defconstant +ipv6-recv-pktinfo+   61))

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
  (defconstant +af-inet6+           10)      ; Linux
  (defconstant +ip-recv-pktinfo+     8)      ; IP_PKTINFO
  (defconstant +ip-pktinfo-cmsg+     8)
  (defconstant +ipv6-recv-pktinfo+   49))

#-(or darwin linux)
(error "0conf transport: unsupported OS (need Darwin or Linux socket constants).")

;;; Interface enumeration constants (shared across Darwin/Linux).
(defconstant +af-inet+          2)
(defconstant +iff-up+           #x1)
(defconstant +iff-loopback+     #x8)
(defconstant +iff-pointopoint+  #x10)
(defconstant +iff-multicast+    #x8000)

;;; --- ancillary data: which interface did this datagram arrive on? ----------
;;;
;;; All our sockets bind INADDR_ANY:5353 with SO_REUSEPORT, so the kernel may
;;; hand a multicast datagram to any socket in the reuse group — not necessarily
;;; the one that joined the group on the interface the packet came in on.  The
;;; socket a packet was read from therefore does not identify the link.  Asking
;;; for IP_PKTINFO / IPV6_PKTINFO makes recvmsg() attach the receiving interface
;;; index, which does.
;;;
;;; CMSG_DATA sits 16 octets into the header on both platforms, but the header
;;; itself differs: cmsg_len is 4 octets on Darwin and 8 on Linux, moving the
;;; level and type fields with it.  The offsets above capture that; the walk
;;; below is otherwise identical, and is pure so it can be tested against
;;; synthetic buffers of either shape.

(defconstant +cmsg-data-offset+ 16
  "Where a control message's payload starts.  Darwin's cmsghdr is 12 octets but
CMSG_DATA aligns it up to 16, which is also Linux's header size.")

(defstruct (cmsg-layout
            (:constructor make-cmsg-layout (len-size level-offset type-offset
                                            ip-type ipv6-type)))
  "The shape of a struct cmsghdr, and the PKTINFO message numbers, for one OS.
Kept as data rather than read-time conditionals so the walk can be exercised
against both platforms' layouts from either one — otherwise half of this file's
trickiest parsing would only ever be tested on the machine that runs it."
  (len-size 8) (level-offset 8) (type-offset 12) (ip-type 8) (ipv6-type 50))

(defparameter *darwin-cmsg-layout* (make-cmsg-layout 4 4 8 26 46)
  "cmsg_len is u_int32_t; IP_PKTINFO is 26 and IPV6_PKTINFO is 46.")

(defparameter *linux-cmsg-layout* (make-cmsg-layout 8 8 12 8 50)
  "cmsg_len is size_t; IP_PKTINFO is 8 and IPV6_PKTINFO is 50.")

(defparameter *cmsg-layout*
  #+darwin *darwin-cmsg-layout*
  #+linux *linux-cmsg-layout*
  "The layout this build's kernel actually uses.")

(defun cmsg-align (n)
  "Round N up to the 8-octet boundary control messages are padded to."
  (logand (+ n 7) (lognot 7)))

(defun decode-native-uint (octets offset size)
  "Read SIZE octets at OFFSET as a native-endian unsigned integer.  Ancillary
data is raw host-order C structs, not the network order the DNS codec deals in."
  (let ((value 0))
    #+big-endian
    (dotimes (i size value)
      (setf value (logior (ash value 8) (aref octets (+ offset i)))))
    #-big-endian
    (loop for i downfrom (1- size) to 0
          do (setf value (logior (ash value 8) (aref octets (+ offset i))))
          finally (return value))))

(defun control-interface-index (control &optional (length (length control))
                                          (layout *cmsg-layout*))
  "The interface index the datagram arrived on, from the LENGTH octets of
ancillary data in CONTROL, or NIL if it is not there.

struct in_pktinfo opens with ipi_ifindex, so the v4 index is at the start of the
payload; struct in6_pktinfo puts ipi6_ifindex after the 16-octet address, so the
v6 index is at payload+16.  Anything malformed — a header that runs past the
buffer, a length below the header size — ends the walk rather than being
guessed at, and since a control message is never shorter than its header the
walk always advances.  An index of 0 — the API's \"unspecified\", which Darwin
reports for looped-back traffic — is treated as absent."
  (let ((offset 0))
    (loop
      (when (> (+ offset +cmsg-data-offset+) length)
        (return nil))
      (let ((len (decode-native-uint control offset (cmsg-layout-len-size layout)))
            (level (decode-native-uint
                    control (+ offset (cmsg-layout-level-offset layout)) 4))
            (type (decode-native-uint
                   control (+ offset (cmsg-layout-type-offset layout)) 4))
            (data (+ offset +cmsg-data-offset+)))
        (when (or (< len +cmsg-data-offset+)
                  (> (+ offset len) length))
          (return nil))
        (let ((index
                (cond
                  ((and (= level +ipproto-ip+) (= type (cmsg-layout-ip-type layout))
                        (<= (+ data 4) length))
                   (decode-native-uint control data 4))
                  ((and (= level +ipproto-ipv6+) (= type (cmsg-layout-ipv6-type layout))
                        (<= (+ data 20) length))
                   (decode-native-uint control (+ data 16) 4)))))
          ;; Index 0 is the sockets API's "unspecified" — Darwin reports it for
          ;; looped-back traffic.  That is no more an answer than no PKTINFO at
          ;; all, so keep looking rather than hand back a link that cannot match.
          (when (and index (plusp index))
            (return index)))
        (incf offset (cmsg-align len))))))

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

;;; --- recvmsg(): the datagram plus its ancillary data ------------------------
;;;
;;; struct msghdr differs between the two platforms in two fields: msg_iovlen is
;;; size_t on Linux and int on Darwin, and msg_controllen is size_t on Linux and
;;; socklen_t on Darwin.  Natural alignment takes care of the padding that falls
;;; out of that.

(sb-alien:define-alien-type nil
  (sb-alien:struct iovec
    (iov-base (sb-alien:* t))
    (iov-len  sb-alien:unsigned-long)))

#+darwin
(sb-alien:define-alien-type nil
  (sb-alien:struct msghdr
    (msg-name       (sb-alien:* t))
    (msg-namelen    sb-alien:unsigned-int)
    (msg-iov        (sb-alien:* t))
    (msg-iovlen     sb-alien:int)
    (msg-control    (sb-alien:* t))
    (msg-controllen sb-alien:unsigned-int)
    (msg-flags      sb-alien:int)))

#+linux
(sb-alien:define-alien-type nil
  (sb-alien:struct msghdr
    (msg-name       (sb-alien:* t))
    (msg-namelen    sb-alien:unsigned-int)
    (msg-iov        (sb-alien:* t))
    (msg-iovlen     sb-alien:unsigned-long)
    (msg-control    (sb-alien:* t))
    (msg-controllen sb-alien:unsigned-long)
    (msg-flags      sb-alien:int)))

(sb-alien:define-alien-routine ("recvmsg" %recvmsg) sb-alien:long
  (fd    sb-alien:int)
  (msg   (sb-alien:* (sb-alien:struct msghdr)))
  (flags sb-alien:int))

(defconstant +recv-control-size+ 256
  "Room for the ancillary data recvmsg attaches.  A PKTINFO message is well under
64 octets; 256 leaves slack for anything else the kernel wants to add.")

(defconstant +recv-name-size+ 128
  "Room for the peer sockaddr — sockaddr_in6 is 28 octets.")

(defun sockaddr-octets-family (octets)
  "The address family from a sockaddr the kernel filled in.  Darwin leads with
sa_len then sa_family; Linux has a native-order 16-bit sa_family."
  (when (>= (length octets) 2)
    #+darwin (aref octets 1)
    #+linux  (decode-native-uint octets 0 2)))

(defun parse-sockaddr-peer (octets)
  "(values host-string port) from a peer sockaddr, or (values NIL NIL).
sockaddr_in and sockaddr_in6 agree on both platforms about where the port sits
(offset 2, network order — this one field really is big-endian) and where the
address does: offset 4 for v4, offset 8 for v6, past the flowinfo."
  (let ((family (sockaddr-octets-family octets)))
    (flet ((port () (+ (ash (aref octets 2) 8) (aref octets 3))))
      (cond
        ((and (eql family +af-inet+) (>= (length octets) 8))
         (values (format-ipv4 (subseq octets 4 8)) (port)))
        ((and (eql family +af-inet6+) (>= (length octets) 24))
         (values (format-ipv6 (subseq octets 8 24)) (port)))
        (t (values nil nil))))))

(defun recvmsg-datagram (fd max)
  "One datagram via recvmsg(), which unlike recvfrom() also hands back the
ancillary data.  Returns (values octets peer-host peer-port interface-index)."
  (let ((buffer (make-array max :element-type '(unsigned-byte 8)))
        (name (make-array +recv-name-size+ :element-type '(unsigned-byte 8)
                                           :initial-element 0))
        (control (make-array +recv-control-size+ :element-type '(unsigned-byte 8)
                                                 :initial-element 0)))
    (sb-sys:with-pinned-objects (buffer name control)
      (sb-alien:with-alien ((iov (sb-alien:struct iovec))
                            (msg (sb-alien:struct msghdr)))
        (setf (sb-alien:slot iov 'iov-base)
              (sb-alien:sap-alien (sb-sys:vector-sap buffer) (sb-alien:* t))
              (sb-alien:slot iov 'iov-len) max
              (sb-alien:slot msg 'msg-name)
              (sb-alien:sap-alien (sb-sys:vector-sap name) (sb-alien:* t))
              (sb-alien:slot msg 'msg-namelen) +recv-name-size+
              (sb-alien:slot msg 'msg-iov)
              (sb-alien:cast (sb-alien:addr iov) (sb-alien:* t))
              (sb-alien:slot msg 'msg-iovlen) 1
              (sb-alien:slot msg 'msg-control)
              (sb-alien:sap-alien (sb-sys:vector-sap control) (sb-alien:* t))
              (sb-alien:slot msg 'msg-controllen) +recv-control-size+
              (sb-alien:slot msg 'msg-flags) 0)
        (let ((n (%recvmsg fd (sb-alien:addr msg) 0)))
          (when (minusp n)
            (error "recvmsg() failed on fd ~D" fd))
          (multiple-value-bind (host port)
              (parse-sockaddr-peer (subseq name 0 (min (length name)
                                                       (sb-alien:slot msg 'msg-namelen))))
            (values (subseq buffer 0 n) host port
                    (control-interface-index
                     control (min +recv-control-size+
                                  (sb-alien:slot msg 'msg-controllen))))))))))

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
        (set-sockopt-int fd +ipproto-ip+ +ip-multicast-loop+ 1))
      ;; Best-effort: without it we simply do not learn the arrival interface.
      (ignore-errors (set-sockopt-int fd +ipproto-ip+ +ip-recv-pktinfo+ 1)))
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
        (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-loop+ 1))
      (ignore-errors (set-sockopt-int fd +ipproto-ipv6+ +ipv6-recv-pktinfo+ 1)))
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
      (set-sockopt-int fd +ipproto-ip+ +ip-multicast-loop+ 1)
      (ignore-errors (set-sockopt-int fd +ipproto-ip+ +ip-recv-pktinfo+ 1)))
    (%make-mdns-socket :socket sock :family :ipv4
                       :interface-name (net-interface-name iface)
                       :interface-address addr
                       :interface-index (net-interface-index iface))))

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
      (set-sockopt-int fd +ipproto-ipv6+ +ipv6-multicast-loop+ 1)
      (ignore-errors (set-sockopt-int fd +ipproto-ipv6+ +ipv6-recv-pktinfo+ 1)))
    (%make-mdns-socket :socket sock :family :ipv6
                       :interface-name (net-interface-name iface)
                       :interface-index index)))

;;; --- reconciling sockets with the live interface list -----------------------
;;;
;;; The set of usable interfaces is not fixed for the life of a process: Wi-Fi
;;; reassociates, a VPN comes up, a laptop is docked, DHCP hands out a new
;;; address.  These let the responder diff what it has open against what is
;;; actually there.  They are pure — no socket is opened or closed here — so the
;;; reconciliation logic is testable without a network.

(defun mdns-socket-key (mdns)
  "Identity of the link a socket serves: NIC name, address family, and whatever
pins it to that NIC.  An interface that keeps its name but picks up a new IPv4
address is a different link as far as IP_MULTICAST_IF is concerned, so the key
changes and the socket gets replaced."
  (list (mdns-socket-interface-name mdns)
        (mdns-socket-family mdns)
        (mdns-socket-interface-address mdns)
        (mdns-socket-interface-index mdns)))

(defun interface-socket-specs (interfaces)
  "One (FAMILY IFACE) spec per socket that INTERFACES calls for — an IPv4 socket
for every NIC with an address, an IPv6 socket for every NIC that has v6."
  (loop for iface in interfaces
        when (net-interface-ipv4 iface) collect (list :ipv4 iface)
        when (net-interface-has-v6 iface) collect (list :ipv6 iface)))

(defun socket-spec-key (spec)
  "The MDNS-SOCKET-KEY the socket built from SPEC will have."
  (destructuring-bind (family iface) spec
    (list (net-interface-name iface) family
          (when (eq family :ipv4) (net-interface-ipv4 iface))
          (net-interface-index iface))))

(defun plan-socket-changes (sockets specs)
  "Diff the sockets we hold against the sockets the current interface list calls
for.  Returns (values specs-to-open sockets-to-close)."
  (let ((have (mapcar #'mdns-socket-key sockets))
        (want (mapcar #'socket-spec-key specs)))
    (values (remove-if (lambda (spec) (member (socket-spec-key spec) have :test #'equalp))
                       specs)
            (remove-if (lambda (socket) (member (mdns-socket-key socket) want :test #'equalp))
                       sockets))))

(defparameter *max-interface-sockets* 32
  "Ceiling on how many sockets the responder opens.  A host with very many
interfaces — a container host, a router, a machine full of tunnels — would
otherwise get a socket and a listener thread per NIC per family, which costs more
than it discovers.")

(defvar *capped-interface-count* nil
  "How many specs the last cap dropped, so a standing over-cap condition is
reported once rather than at every rescan.")

(defun usable-socket-specs (interfaces &optional (cap *max-interface-sockets*))
  "The socket specs for INTERFACES, held to CAP.  Silently dropping links would
look like interfaces mysteriously not working, so the first time a given number
is dropped it is reported."
  (let* ((specs (interface-socket-specs interfaces))
         (dropped (max 0 (- (length specs) cap))))
    (cond ((zerop dropped)
           (setf *capped-interface-count* nil)
           specs)
          (t
           (unless (eql dropped *capped-interface-count*)
             (setf *capped-interface-count* dropped)
             (warn "0conf: ~D interface sockets wanted, capping at ~D; ~D link~:P ~
will not be served (see *MAX-INTERFACE-SOCKETS*)."
                   (length specs) cap dropped))
           (subseq specs 0 cap)))))

(defun open-socket-for-spec (spec)
  "Open the socket SPEC describes, or NIL if the join fails on that NIC."
  (destructuring-bind (family iface) spec
    (ecase family
      (:ipv4 (ignore-errors (make-ipv4-mdns-socket-on iface)))
      (:ipv6 (ignore-errors (make-ipv6-mdns-socket-on iface))))))

(defun close-mdns-socket (mdns)
  (ignore-errors (sb-bsd-sockets:socket-close (mdns-socket-socket mdns))))

;;; --- send / receive --------------------------------------------------------

(defun mdns-send (mdns octets &key host (port +mdns-port+))
  "Send OCTETS to HOST:PORT.  HOST defaults to the mDNS group for the socket's
address family; it is parsed as IPv4 or IPv6 to match.

A message over the RFC 6762 §17 hard ceiling is dropped rather than sent: the
senders above this layer split their record sets to stay well under it, so
arriving here oversized means a single record that cannot legally be put on the
wire at all."
  (when (> (length octets) +hard-max-message-size+)
    (warn "0conf: dropping a ~D-octet mDNS message; RFC 6762 §17 caps a packet at ~
9000 bytes including IP and UDP headers."
          (length octets))
    (return-from mdns-send nil))
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
  "Block for one datagram.  Returns (values octets peer-host peer-port ifindex).

IFINDEX is the interface the datagram actually arrived on, which the socket it
was read from does not tell us (see the ancillary-data section above).  It is
NIL when the kernel did not supply it — an OS that refused IP_PKTINFO, or the
fallback path below — and every caller treats that as \"unknown\" rather than
assuming anything."
  (handler-case (recvmsg-datagram
                 (sb-bsd-sockets:socket-file-descriptor (mdns-socket-socket mdns))
                 max)
    ;; recvmsg is the whole reason we can attribute an interface, but it must
    ;; never be the reason a datagram is lost: fall back to the plain path.
    (error ()
      (multiple-value-bind (buffer size host port)
          (sb-bsd-sockets:socket-receive (mdns-socket-socket mdns)
                                         (make-array max :element-type '(unsigned-byte 8))
                                         max)
        (values (subseq buffer 0 size) (host->string host) port nil)))))

(defun mdns-recv-timeout (mdns seconds)
  "Like MDNS-RECV but returns NIL if nothing arrives within SECONDS."
  (let ((fd (sb-bsd-sockets:socket-file-descriptor (mdns-socket-socket mdns))))
    (when (sb-sys:wait-until-fd-usable fd :input seconds)
      (mdns-recv mdns))))
