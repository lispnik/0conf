;;;; 0conf.asd — pure Common Lisp mDNS / DNS-SD (zeroconf) implementation.

(defsystem "0conf"
  :description "Pure Common Lisp mDNS (RFC 6762) and DNS-SD (RFC 6763) implementation."
  :author "Mike Kennedy"
  :license "MIT"
  :version "0.0.1"
  :depends-on ("alexandria" "nibbles" "bordeaux-threads" "sb-bsd-sockets")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "constants")
               (:file "octets")       ; wire codec: byte cursor + name compression
               (:file "records")      ; CLOS resource records + rdata codecs
               (:file "message")      ; DNS header + sections
               (:file "cache")        ; TTL cache + cache-flush semantics
               (:file "transport")    ; SBCL multicast UDP socket (v4 + v6)
               (:file "service-info") ; DNS-SD service expansion / reassembly
               (:file "responder")    ; probing, conflict resolution, announce
               (:file "browser")      ; DNS-SD discovery (snapshot + live)
               (:file "0conf"))       ; public start/stop API
  :in-order-to ((test-op (test-op "0conf/test"))))

(defsystem "0conf/test"
  :description "FiveAM test suite for 0conf."
  :depends-on ("0conf" "fiveam")
  :serial t
  :pathname "test"
  :components ((:file "package")
               (:file "codec-tests")
               (:file "records-tests")
               (:file "cache-tests")
               (:file "service-tests")
               (:file "responder-tests")
               (:file "browser-tests")
               (:file "transport-tests")
               (:file "integration-tests"))
  :perform (test-op (o c)
             (uiop:symbol-call :0conf/test '#:run-tests)))
