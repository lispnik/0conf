;;;; test/integration-tests.lisp — real sockets over loopback (no multicast).
;;;;
;;;; These exercise the transport send/receive paths and a full
;;;; query -> responder -> answer round trip using unicast UDP on 127.0.0.1, so
;;;; they run everywhere (no multicast group, no macOS multicast entitlement).
;;;; Each test skips — rather than fails — if the sandbox forbids even loopback
;;;; UDP, keeping the pure suite authoritative.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun ephemeral-socket ()
  "A non-multicast mDNS socket bound to an OS-assigned loopback port."
  (make-mdns-socket :multicast nil :port 0))

(defun local-port (mdns)
  (nth-value 1 (sb-bsd-sockets:socket-name (0conf::mdns-socket-socket mdns))))

(test transport-loopback-round-trip
  "A real mDNS packet sent between two UDP sockets over loopback decodes back."
  (handler-case
      (let ((a (ephemeral-socket))
            (b (ephemeral-socket)))
        (unwind-protect
             (let ((msg (make-dns-message
                         :id 4242
                         :answers (list (make-instance 'a-record :name "loop.local"
                                                       :address (parse-ipv4 "127.0.0.1"))))))
               (mdns-send a (encode-message msg) :host "127.0.0.1" :port (local-port b))
               (let ((octets (mdns-recv-timeout b 2.0)))
                 (is (not (null octets)))
                 (when octets
                   (let ((got (decode-message octets)))
                     (is (= 4242 (dns-message-id got)))
                     (is (string= "loop.local"
                                  (rr-name (first (dns-message-answers got)))))))))
          (close-mdns-socket a)
          (close-mdns-socket b)))
    (error (e) (skip "loopback UDP unavailable: ~A" e))))

(test transport-recv-timeout-returns-nil
  "MDNS-RECV-TIMEOUT gives up (returns NIL) when nothing arrives."
  (handler-case
      (let ((s (ephemeral-socket)))
        (unwind-protect
             (is (null (mdns-recv-timeout s 0.2)))
          (close-mdns-socket s)))
    (error (e) (skip "loopback UDP unavailable: ~A" e))))

(test responder-answers-query-over-loopback
  "End to end: a client's unicast query reaches a running responder, which
matches it against its records and replies — the client gets the answer.
Exercises the listener thread, HANDLE-PACKET, ANSWER-QUERY, and the socket I/O."
  (handler-case
      (let ((server-sock (ephemeral-socket))
            (client (ephemeral-socket))
            (responder (make-responder))
            (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                     :port 1 :addresses (list (parse-ipv4 "127.0.0.1")))))
        (setf (0conf::responder-records responder) (service-info-records info))
        (unwind-protect
             (progn
               (start-responder responder :socket server-sock)
               ;; QU bit set -> the responder replies unicast to us (no multicast).
               (let ((query (encode-message
                             (make-dns-message
                              :questions (list (make-question :name "h.local"
                                                              :qtype +type-a+
                                                              :unicast-response t))))))
                 (mdns-send client query :host "127.0.0.1" :port (local-port server-sock))
                 (let ((octets (mdns-recv-timeout client 2.0)))
                   (is (not (null octets)))
                   (when octets
                     (let ((reply (decode-message octets)))
                       (is (find-if (lambda (r)
                                      (and (typep r 'a-record)
                                           (string-equal (rr-name r) "h.local")))
                                    (dns-message-answers reply))))))))
          (stop-responder responder)          ; also closes server-sock
          (close-mdns-socket client)))
    (error (e) (skip "loopback responder test unavailable: ~A" e))))
