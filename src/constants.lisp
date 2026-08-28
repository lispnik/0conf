;;;; constants.lisp — DNS/mDNS numeric constants (RFC 6762 / 6763).

(in-package #:0conf)

;;; Record classes.  In mDNS the top bit of the rrclass field is overloaded:
;;; on a query it means "unicast response requested", on a response it means
;;; "cache-flush".  We keep the plain class here and mask the bit separately.
(defconstant +class-in+        1)
(defconstant +cache-flush-bit+ #x8000)

;;; Resource record types we care about for mDNS + DNS-SD.
(defconstant +type-a+     1)
(defconstant +type-ns+    2)
(defconstant +type-cname+ 5)
(defconstant +type-ptr+   12)
(defconstant +type-txt+   16)
(defconstant +type-aaaa+  28)
(defconstant +type-srv+   33)
(defconstant +type-nsec+  47)
(defconstant +type-any+   255)

;;; Transport.
(defconstant +mdns-port+ 5353)

;;; Header flags for a typical mDNS response: QR=1 (response), AA=1 (authoritative).
(defconstant +flag-response+ #x8400)

;;; TC (truncation).  On an mDNS *query* it does not mean "the answer was cut
;;; short" as in unicast DNS: it means "my known-answer list continues in the
;;; packets that follow" (RFC 6762 §7.2).
(defconstant +flag-truncated+ #x0200)

;;; Message size (RFC 6762 §17).  A message may be as large as the interface MTU
;;; less the IP (20 v4 / 40 v6) and UDP (8) headers, but the RFC advises keeping
;;; packets under 1500 bytes, since jumbo frames and IP fragment reassembly are
;;; not universally handled — notably by devices that offload packet reception to
;;; the NIC while asleep.  1400 leaves room for either header size with margin.
(defparameter *max-message-size* 1400
  "Target ceiling in octets for one outgoing mDNS message; larger record sets are
split across several packets.")

;;; The hard limit: "a Multicast DNS packet, including IP and UDP headers, MUST
;;; NOT exceed 9000 bytes" (§17).  Worst case headers are IPv6's 40 + UDP's 8.
(defconstant +hard-max-message-size+ (- 9000 40 8))

;;; Multicast groups (strings -> defparameter to survive reload without EQL grief).
(defparameter +mdns-group-v4+ "224.0.0.251")
(defparameter +mdns-group-v6+ "ff02::fb")
