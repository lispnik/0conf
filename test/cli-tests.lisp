;;;; test/cli-tests.lisp — the CLI's argument conversion.
;;;;
;;;; Only IFACE-ARG is covered: everything else in the CLI is I/O against the
;;;; network or the terminal.  Interface names differ per machine, so the
;;;; expected values are derived from GETIFADDRS at run time rather than
;;;; hardcoded, and a case with no suitable NIC skips.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun iface-arg-for (interface family)
  "IFACE-ARG with the CLI's two specials bound, as MAIN would bind them."
  (let ((0conf-cli::*interface* interface)
        (0conf-cli::*family* family))
    (0conf-cli::iface-arg)))

(defun some-interface (predicate)
  (find-if predicate (list-interfaces :include-loopback t :multicast-only nil)))

(test iface-arg-nil-when-unset
  (is (null (iface-arg-for nil :ipv4)))
  (is (null (iface-arg-for nil :ipv6))))

(test iface-arg-passes-raw-forms-through
  "A dotted-quad (v4) and an index (v6) are what the socket layer wants already."
  (is (string= "192.168.1.42" (iface-arg-for "192.168.1.42" :ipv4)))
  (is (eql 3 (iface-arg-for "3" :ipv6))))

(test iface-arg-resolves-name-to-ipv4-address
  (let ((iface (some-interface #'net-interface-ipv4)))
    (if iface
        (is (string= (format-ipv4 (net-interface-ipv4 iface))
                     (iface-arg-for (net-interface-name iface) :ipv4)))
        (skip "no interface with an IPv4 address"))))

(test iface-arg-resolves-name-to-interface-index
  (let ((iface (some-interface #'net-interface-index)))
    (if iface
        (is (eql (net-interface-index iface)
                 (iface-arg-for (net-interface-name iface) :ipv6)))
        (skip "no interface with an index"))))

(test iface-arg-rejects-unknown-name
  (signals 0conf-cli::cli-error (iface-arg-for "no-such-nic0" :ipv4))
  (signals 0conf-cli::cli-error (iface-arg-for "no-such-nic0" :ipv6)))

(test iface-arg-rejects-malformed-address
  "Digits and dots reads as a botched address, not as a NIC name."
  (signals 0conf-cli::cli-error (iface-arg-for "300.1.2.3" :ipv4))
  (signals 0conf-cli::cli-error (iface-arg-for "192.168.1" :ipv4)))

(test iface-arg-rejects-v4-request-on-v6-only-interface
  (let ((iface (some-interface (lambda (i) (and (net-interface-has-v6 i)
                                                (null (net-interface-ipv4 i)))))))
    (if iface
        (signals 0conf-cli::cli-error
          (iface-arg-for (net-interface-name iface) :ipv4))
        (skip "no interface without an IPv4 address"))))
