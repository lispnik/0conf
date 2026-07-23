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

;;; Multicast groups (strings -> defparameter to survive reload without EQL grief).
(defparameter +mdns-group-v4+ "224.0.0.251")
(defparameter +mdns-group-v6+ "ff02::fb")
