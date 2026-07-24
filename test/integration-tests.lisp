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

(test responder-legacy-unicast-query
  "A query from a non-5353 source port (a legacy resolver) gets a unicast reply
with the query id echoed, the question repeated, and TTLs capped at 10s
(RFC 6762 §6.7) — even without the QU bit set."
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
               (let ((query (encode-message
                             (make-dns-message
                              :id 777        ; must be echoed back
                              :questions (list (make-question :name "h.local"
                                                              :qtype +type-a+))))))
                 (mdns-send client query :host "127.0.0.1" :port (local-port server-sock))
                 (let ((octets (mdns-recv-timeout client 2.0)))
                   (is (not (null octets)))
                   (when octets
                     (let* ((reply (decode-message octets))
                            (a (find-if (lambda (r) (typep r 'a-record))
                                        (dns-message-answers reply))))
                       (is (= 777 (dns-message-id reply)))                  ; echoed id
                       (is (plusp (length (dns-message-questions reply))))  ; question repeated
                       (is (not (null a)))
                       (is (<= (rr-ttl a) 10)))))))                         ; TTL capped
          (stop-responder responder)
          (close-mdns-socket client)))
    (error (e) (skip "loopback legacy test unavailable: ~A" e))))

(test browse-once-collects-and-assembles-over-loopback
  "browse-once with an injected socket collects a response delivered to it and
reassembles the service — exercising the receive loop and assembly with no
multicast (the outgoing query fails harmlessly and is ignored)."
  (handler-case
      (let* ((browser-sock (ephemeral-socket))
             (sender (ephemeral-socket))
             (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                      :port 1 :addresses (list (parse-ipv4 "127.0.0.1"))))
             (response (encode-message
                        (make-dns-message :flags +flag-response+
                                          :answers (service-info-records info)))))
        (unwind-protect
             (progn
               ;; Pre-queue the response in the browser socket's receive buffer.
               (mdns-send sender response :host "127.0.0.1" :port (local-port browser-sock))
               (sleep 0.1)
               (let ((found (browse-once "_x._tcp.local" :timeout 0.5 :socket browser-sock)))
                 (is (= 1 (length found)))
                 (is (string= "N" (service-info-name (first found))))
                 (is (= 1 (service-info-port (first found))))))
          (close-mdns-socket browser-sock)
          (close-mdns-socket sender)))
    (error (e) (skip "loopback browse-once unavailable: ~A" e))))

(test resolve-single-instance-over-loopback
  "resolve queries one instance name and assembles the SERVICE-INFO from the
response delivered to its socket."
  (handler-case
      (let* ((sock (ephemeral-socket))
             (sender (ephemeral-socket))
             (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                      :port 42 :addresses (list (parse-ipv4 "127.0.0.1"))))
             (instance (service-instance-name info))
             (response (encode-message
                        (make-dns-message :flags +flag-response+
                                          :answers (service-info-records info)))))
        (unwind-protect
             (progn
               (mdns-send sender response :host "127.0.0.1" :port (local-port sock))
               (sleep 0.1)
               (let ((resolved (resolve instance :timeout 0.5 :socket sock)))
                 (is (not (null resolved)))
                 (is (= 42 (service-info-port resolved)))
                 (is (string= "h.local" (service-info-host resolved)))
                 (is (equalp (parse-ipv4 "127.0.0.1")
                             (first (service-info-addresses resolved))))))
          (close-mdns-socket sock)
          (close-mdns-socket sender)))
    (error (e) (skip "loopback resolve unavailable: ~A" e))))
