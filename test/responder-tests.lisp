;;;; test/responder-tests.lisp — probe conflict detection + rename.
;;;;
;;;; These drive the responder's packet handler directly (no socket), so they
;;;; test the conflict/rename logic deterministically without live multicast.

(in-package #:0conf/test)

(in-suite 0conf-tests)

(test next-instance-name-bumps
  "RFC 6762 §9 renaming: append/increment a \" (N)\" suffix."
  (is (string= "Printer (2)"  (0conf::next-instance-name "Printer")))
  (is (string= "Printer (3)"  (0conf::next-instance-name "Printer (2)")))
  (is (string= "Printer (10)" (0conf::next-instance-name "Printer (9)")))
  ;; A non-numeric parenthesised suffix is not a counter.
  (is (string= "Widget (x) (2)" (0conf::next-instance-name "Widget (x)"))))

(defun a-response-for (name)
  "Encoded mDNS *response* answering with an A record for NAME."
  (encode-message
   (make-dns-message
    :flags +flag-response+
    :answers (list (make-instance 'a-record :name name :cache-flush t
                                            :address (parse-ipv4 "10.0.0.1"))))))

(test probe-detects-conflict-on-response
  "Someone else answering for the name we're probing is a conflict."
  (let ((r (make-responder)))
    (setf (0conf::responder-probing r) "Printer._ipp._tcp.local")
    (0conf::handle-packet r (a-response-for "Printer._ipp._tcp.local") "10.0.0.1" 5353)
    (is (0conf::responder-conflict r))))

(test probe-detects-conflict-case-insensitively
  (let ((r (make-responder)))
    (setf (0conf::responder-probing r) "Printer._ipp._tcp.local")
    (0conf::handle-packet r (a-response-for "PRINTER._ipp._tcp.local") "10.0.0.1" 5353)
    (is (0conf::responder-conflict r))))

(test probe-ignores-unrelated-response
  "A response for a different name is not our conflict."
  (let ((r (make-responder)))
    (setf (0conf::responder-probing r) "Printer._ipp._tcp.local")
    (0conf::handle-packet r (a-response-for "Other._ipp._tcp.local") "10.0.0.1" 5353)
    (is (not (0conf::responder-conflict r)))))

(test probe-ignores-queries
  "A *query* for the probed name is another prober, not a defender — it must not
trip the conflict flag here (simultaneous-prober tiebreak is a separate TODO)."
  (let ((r (make-responder))
        (query (encode-message
                (make-dns-message
                 :questions (list (make-question :name "Printer._ipp._tcp.local"
                                                 :qtype +type-any+))))))
    (setf (0conf::responder-probing r) "Printer._ipp._tcp.local")
    (0conf::handle-packet r query "10.0.0.1" 5353)
    (is (not (0conf::responder-conflict r)))))

(test not-probing-means-no-conflict
  "With no active probe, an incoming response never sets the flag."
  (let ((r (make-responder)))
    (0conf::handle-packet r (a-response-for "Printer._ipp._tcp.local") "10.0.0.1" 5353)
    (is (not (0conf::responder-conflict r)))))

(test update-service-txt-replaces-record
  "update-service-txt swaps the instance's TXT record and mutates the info."
  (let* ((responder (make-responder))
         (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :txt '(("v" . "1")))))
    (setf (0conf::responder-records responder) (service-info-records info))
    (update-service-txt responder info '(("v" . "2")))
    (let ((txts (remove-if-not (lambda (r) (typep r 'txt-record))
                               (0conf::responder-records responder))))
      (is (= 1 (length txts)))                        ; still exactly one TXT record
      (is (member "v=2" (txt-strings (first txts)) :test #'string=))
      (is (equal '(("v" . "2")) (service-info-txt info))))))

(test next-host-name-bumps
  "RFC 6762 §9 host renaming: append/increment a \"-N\" suffix on the first label."
  (is (string= "myhost-2.local"  (0conf::next-host-name "myhost.local")))
  (is (string= "myhost-3.local"  (0conf::next-host-name "myhost-2.local")))
  (is (string= "my-host-2.local" (0conf::next-host-name "my-host.local"))))

(test host-name-conflict-detected
  "The host name is probed/defended like an instance name: a response for the
host name we're probing is a conflict."
  (let ((r (make-responder)))
    (setf (0conf::responder-probing r) "myhost.local")
    (0conf::handle-packet r (a-response-for "myhost.local") "10.0.0.9" 5353)
    (is (0conf::responder-conflict r))))

(test pending-ka-expires
  "Orphaned continuation known-answers are evicted after their TTL, not leaked."
  (let ((r (make-responder)))
    (0conf::buffer-known-answers r "10.0.0.2" (list (a-at "h.local" "10.0.0.1")) 1000)
    (0conf::expire-pending-ka r 1002)                 ; within 5s ttl -> kept
    (is (0conf::take-known-answers r "10.0.0.2"))
    (0conf::buffer-known-answers r "10.0.0.2" (list (a-at "h.local" "10.0.0.1")) 1000)
    (0conf::expire-pending-ka r 1010)                 ; past ttl -> evicted
    (is (null (0conf::take-known-answers r "10.0.0.2")))))

;;; --- §8.2 lexicographic tiebreaking ---------------------------------------

(defun a-at (name ip)
  (make-instance 'a-record :name name :cache-flush t :address (parse-ipv4 ip)))

(test compare-record-sets-orders-by-rdata
  (let ((lo (list (a-at "h.local" "1.2.3.4")))
        (hi (list (a-at "h.local" "1.2.3.5"))))
    (is (eq :lose (0conf::compare-record-sets lo hi)))
    (is (eq :win  (0conf::compare-record-sets hi lo)))
    (is (eq :tie  (0conf::compare-record-sets lo (list (a-at "h.local" "1.2.3.4")))))
    ;; a longer set (superset prefix) is lexicographically later
    (is (eq :win  (0conf::compare-record-sets
                   (list (a-at "h.local" "1.2.3.4") (a-at "h.local" "1.2.3.9"))
                   (list (a-at "h.local" "1.2.3.4")))))))

(defun probe-query-for (name ip)
  "Encoded *query* from a simultaneous prober: question for NAME with a proposed
A record in the Authority section."
  (encode-message
   (make-dns-message
    :questions (list (make-question :name name :qtype +type-any+))
    :authorities (list (a-at name ip)))))

(defun probing-responder (name ip)
  (let ((r (make-responder)))
    (setf (0conf::responder-probing r) name
          (0conf::responder-probe-records r) (list (a-at name ip)))
    r))

(test tiebreak-loss-sets-conflict
  "Their proposed data is lexicographically later -> we lose -> rename."
  (let ((r (probing-responder "P._x._tcp.local" "10.0.0.5")))
    (0conf::handle-packet r (probe-query-for "P._x._tcp.local" "10.0.0.9")
                          "10.0.0.9" 5353)
    (is (0conf::responder-conflict r))))

(test tiebreak-win-no-conflict
  "Ours is later -> we win -> keep the name."
  (let ((r (probing-responder "P._x._tcp.local" "10.0.0.9")))
    (0conf::handle-packet r (probe-query-for "P._x._tcp.local" "10.0.0.5")
                          "10.0.0.5" 5353)
    (is (not (0conf::responder-conflict r)))))

(test tiebreak-tie-no-conflict
  "Identical proposed data is not a conflict (could be our own probe echoed)."
  (let ((r (probing-responder "P._x._tcp.local" "10.0.0.5")))
    (0conf::handle-packet r (probe-query-for "P._x._tcp.local" "10.0.0.5")
                          "10.0.0.5" 5353)
    (is (not (0conf::responder-conflict r)))))

;;; --- on-demand NSEC in query responses (§6.1) -----------------------------

(defun responder-advertising (info)
  (let ((r (make-responder)))
    (setf (0conf::responder-records r) (service-info-records info))
    r))

(defun query-msg (name qtype)
  (make-dns-message :questions (list (make-question :name name :qtype qtype))))

(defparameter *ipv4-service*
  (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                     :port 1 :addresses (list (parse-ipv4 "10.0.0.1"))))

(test nsec-accompanies-positive-answer
  "A positive answer carries our NSEC for that name in Additional."
  (let ((r (responder-advertising *ipv4-service*)))
    (multiple-value-bind (answers additionals)
        (0conf::build-response r (query-msg "h.local" +type-a+))
      (is (find-if (lambda (x) (typep x 'a-record)) answers))
      (is (find-if (lambda (x) (typep x 'nsec-record)) additionals)))))

(test nsec-negative-answer-for-absent-type
  "IPv4-only host queried for AAAA answers with the NSEC (negative response)."
  (let ((r (responder-advertising *ipv4-service*)))
    (multiple-value-bind (answers additionals)
        (0conf::build-response r (query-msg "h.local" +type-aaaa+))
      (declare (ignore additionals))
      (is (= 1 (length answers)))
      (is (typep (first answers) 'nsec-record))
      (is (not (member +type-aaaa+ (nsec-types (first answers))))))))

(test duplicate-response-suppression
  "surviving-answers drops an answer a peer already sent (now in the cache) but
keeps one that was already matched up front (our own looped-back record)."
  (let* ((rec (make-instance 'a-record :name "h.local" :cache-flush t
                                       :address (parse-ipv4 "10.0.0.1")))
         (cache (make-cache)))
    (cache-add cache (make-instance 'a-record :name "h.local"
                                              :address (parse-ipv4 "10.0.0.1")))
    ;; peer's copy is in the cache and it wasn't ours -> suppressed
    (is (null (0conf::surviving-answers (list rec) cache '())))
    ;; but if it was already matched (already-matched contains it) -> kept
    (is (equal (list rec) (0conf::surviving-answers (list rec) cache (list rec))))
    ;; nothing matching in the cache -> kept
    (let ((other (make-instance 'a-record :name "h.local"
                                          :address (parse-ipv4 "10.0.0.9"))))
      (is (equal (list other) (0conf::surviving-answers (list other) cache '()))))))

(test known-answer-suppression-across-continuation
  "build-response suppresses an answer listed in a merged known-answer list, as
if it had arrived in a continuation packet (§7.2)."
  (let* ((info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :addresses (list (parse-ipv4 "10.0.0.1"))))
         (r (responder-advertising info))
         (q (make-dns-message
             :questions (list (make-question :name "h.local" :qtype +type-a+))))
         ;; the querier already knows our A record (fresh) — supplied as if merged
         ;; from a continuation packet
         (known (list (make-instance 'a-record :name "h.local" :ttl 120
                                               :address (parse-ipv4 "10.0.0.1")))))
    ;; without the known-answer, we'd answer with the A record
    (is (find-if (lambda (x) (typep x 'a-record)) (0conf::build-response r q)))
    ;; with it in the (merged) known-answers, the A is suppressed
    (is (not (find-if (lambda (x) (typep x 'a-record))
                      (0conf::build-response r q known))))))

(test continuation-packet-buffering
  "A query with known-answers but no questions is buffered per host, not answered."
  (let* ((r (make-responder))
         (ka (make-instance 'a-record :name "h.local" :ttl 120
                                      :address (parse-ipv4 "10.0.0.1")))
         (cont (encode-message (make-dns-message :answers (list ka)))))
    (is (0conf::continuation-packet-p (decode-message cont)))
    (0conf::handle-packet r cont "10.0.0.2" 5353)          ; buffered, no reply attempted
    (let ((buffered (0conf::take-known-answers r "10.0.0.2")))
      (is (= 1 (length buffered)))
      (is (string= "h.local" (rr-name (first buffered)))))
    ;; taken -> buffer now empty
    (is (null (0conf::take-known-answers r "10.0.0.2")))))

(test build-response-aggregates-multiple-questions
  "Answers to all of a query's questions are aggregated into one response (§7.4)."
  (let* ((info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :addresses (list (parse-ipv4 "10.0.0.1"))))
         (r (responder-advertising info))
         (q (make-dns-message
             :questions (list (make-question :name "h.local" :qtype +type-a+)
                              (make-question :name "N._x._tcp.local" :qtype +type-srv+)))))
    (multiple-value-bind (answers additionals) (0conf::build-response r q)
      (declare (ignore additionals))
      (is (find-if (lambda (x) (typep x 'a-record)) answers))
      (is (find-if (lambda (x) (typep x 'srv-record)) answers)))))

(test nsec-not-negative-when-type-present
  "Dual-stack host queried for AAAA gives the real AAAA, not a negative NSEC."
  (let* ((v6 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2))
         (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :addresses (list (parse-ipv4 "10.0.0.1") v6)))
         (r (responder-advertising info)))
    (multiple-value-bind (answers additionals)
        (0conf::build-response r (query-msg "h.local" +type-aaaa+))
      (declare (ignore additionals))
      (is (find-if (lambda (x) (typep x 'aaaa-record)) answers))
      (is (not (find-if (lambda (x) (typep x 'nsec-record)) answers))))))

;;; --- §9 conflict resolution after announcing -------------------------------

(defun registered-responder (&key (name "Printer") (host "myhost.local")
                                  (addresses (list (parse-ipv4 "10.0.0.7"))))
  "A responder holding one announced service, with no sockets and no probing —
so the §9 paths can be driven deterministically.  Returns (values responder info)."
  (let ((r (make-responder))
        (info (make-service-info :type "_ipp._tcp.local" :name name :host host
                                 :port 631 :addresses addresses)))
    (register-service r info :probe nil)
    (values r info)))

(defun peer-address-record (name dotted)
  (make-instance 'a-record :name name :cache-flush t :ttl 120
                           :address (parse-ipv4 dotted)))

(test differing-rdata-at-a-name-we-own-is-a-conflict
  "RFC 6762 §9: another host claiming our host name with a different address."
  (let ((r (registered-responder)))
    (is (0conf::conflicting-record-p
         (0conf::responder-records r)
         (peer-address-record "myhost.local" "10.0.0.99")))))

(test identical-rdata-is-never-a-conflict
  "§9 is explicit: identical rdata is never inconsistent, even from another host
— that is what lets a proxy answer on our behalf.  It is also why our own
looped-back multicast does not make us rename ourselves."
  (let ((r (registered-responder)))
    (is (not (0conf::conflicting-record-p
              (0conf::responder-records r)
              (peer-address-record "myhost.local" "10.0.0.7"))))))

(test a-multi-homed-rrset-does-not-conflict-with-its-own-members
  "Two addresses at one name are one rrset, so seeing either of them back is
consistent — the comparison is against the whole set, not record by record."
  (let ((r (registered-responder :addresses (list (parse-ipv4 "10.0.0.7")
                                                  (parse-ipv4 "192.168.1.5")))))
    (is (not (0conf::conflicting-record-p (0conf::responder-records r)
                                          (peer-address-record "myhost.local" "10.0.0.7"))))
    (is (not (0conf::conflicting-record-p (0conf::responder-records r)
                                          (peer-address-record "myhost.local" "192.168.1.5"))))
    (is (0conf::conflicting-record-p (0conf::responder-records r)
                                     (peer-address-record "myhost.local" "172.16.0.1")))))

(test shared-records-never-conflict
  "A DNS-SD PTR is shared by every instance of the type, so another host's
instance appearing at that name is normal, not a conflict."
  (let ((r (registered-responder)))
    (is (not (0conf::conflicting-record-p
              (0conf::responder-records r)
              (make-instance 'ptr-record :name "_ipp._tcp.local" :ttl 4500
                             :target "Someone Else._ipp._tcp.local"))))))

(test a-goodbye-is-a-withdrawal-not-a-competing-claim
  "A ttl-0 record says the peer is going away; renaming ourselves over it would
be exactly backwards."
  (let ((r (registered-responder))
        (goodbye (make-instance 'a-record :name "myhost.local" :cache-flush t :ttl 0
                                :address (parse-ipv4 "10.0.0.99"))))
    (0conf::detect-record-conflicts r (list goodbye))
    (is (null (0conf::responder-conflicted r)))))

(test a-conflicting-response-queues-the-name-for-reprobing
  "End to end through HANDLE-PACKET: the name lands on the resolver's queue."
  (let ((r (registered-responder)))
    (0conf::handle-packet r (a-response-for "myhost.local") "10.0.0.2" 5353)
    (is (equal '("myhost.local") (0conf::responder-conflicted r)))
    ;; and it is taken exactly once
    (is (equal '("myhost.local") (0conf::take-conflicted r)))
    (is (null (0conf::responder-conflicted r)))))

(test an-unrelated-response-queues-nothing
  (let ((r (registered-responder)))
    (0conf::handle-packet r (a-response-for "someone-else.local") "10.0.0.2" 5353)
    (is (null (0conf::responder-conflicted r)))))

(test conflict-burst-limit-trips-at-fifteen-in-ten-seconds
  "RFC 6762 §8.1: fifteen conflicts in ten seconds and every further probe
attempt must wait.  Older timestamps age out of the window."
  (let ((r (make-responder))
        (now (get-universal-time)))
    (setf (0conf::responder-conflict-times r) (make-list 14 :initial-element now))
    (is (not (0conf::conflict-rate-limited-p r now)))
    (push now (0conf::responder-conflict-times r))
    (is (0conf::conflict-rate-limited-p r now))
    ;; A burst that has aged past the window no longer counts, and is discarded.
    (setf (0conf::responder-conflict-times r)
          (make-list 20 :initial-element (- now 11)))
    (is (not (0conf::conflict-rate-limited-p r now)))
    (is (null (0conf::responder-conflict-times r)))))

(test resolving-a-conflict-reprobes-and-leaves-one-clean-record-set
  "The corrective action withdraws what we held at the name and runs §8 again.
With no peer defending during the re-probe we keep the name — and must end up
registered exactly once, with no duplicated records left behind."
  (multiple-value-bind (r info) (registered-responder)
    (0conf::resolve-conflict r "myhost.local")
    (is (string= "myhost.local" (service-info-host info)))
    (is (= 1 (count info (0conf::responder-services r))))
    (is (= 1 (count-if (lambda (rec) (and (typep rec 'a-record)
                                          (string-equal (rr-name rec) "myhost.local")))
                       (0conf::responder-records r))))))

(test a-large-record-set-is-announced-as-several-packets
  "RFC 6762 §17: an announcement too big for one datagram is split, and each
packet stays under the cap."
  (let* ((records (loop for i from 0 below 60
                        collect (make-instance 'txt-record
                                               :name (format nil "svc~D._x._tcp.local" i)
                                               :cache-flush t :ttl 120
                                               :strings (list (format nil "key=~A"
                                                                      (make-string 60 :initial-element #\x))))))
         (packets (0conf::response-packets nil records '() nil)))
    (is (> (length packets) 1))
    (is (every (lambda (p) (<= (length p) 0conf::*max-message-size*)) packets))
    (is (= (length records)
           (loop for p in packets
                 sum (length (dns-message-answers (decode-message p))))))))

(test a-defended-name-is-surrendered-when-the-conflict-is-resolved
  "The whole point of §9: a peer still asserting our name when we go back to
probing wins it, and we come back under a new one — without the service being
registered twice."
  (multiple-value-bind (r info) (registered-responder)
    (let* ((running t)
           (defender (bordeaux-threads:make-thread
                      (lambda ()
                        ;; Stand in for the other host: answer for the name for
                        ;; as long as we are probing it.
                        (loop while running do
                          (let ((probing (0conf::responder-probing r)))
                            (when (and probing (string-equal probing "myhost.local"))
                              (ignore-errors
                               (0conf::handle-packet r (a-response-for "myhost.local")
                                                     "10.0.0.2" 5353))))
                          (sleep 0.01)))
                      :name "0conf-test-defender")))
      (unwind-protect
           (let ((0conf::*probe-conflict-backoff* 0))
             (0conf::resolve-conflict r "myhost.local"))
        (setf running nil)
        (bordeaux-threads:join-thread defender))
      (is (string= "myhost-2.local" (service-info-host info)))
      (is (= 1 (count info (0conf::responder-services r))))
      (is (find-if (lambda (rec) (and (typep rec 'a-record)
                                      (string-equal (rr-name rec) "myhost-2.local")))
                   (0conf::responder-records r))))))

;;; --- interface changes after startup ---------------------------------------

(test joining-a-link-puts-every-service-back-through-probing
  "RFC 6762 §8.1: an interface coming up is a startup.  The names we hold may
already be taken on the network we just joined, so every service is queued for
the resolver — and host names must be re-probed too, which means forgetting that
we ever claimed them."
  (multiple-value-bind (r info) (registered-responder)
    ;; The fixture registers without probing (it is not on a network), so stand
    ;; in for the claim a probed registration would have recorded.
    (setf (gethash (service-info-host info) (0conf::responder-claimed-hosts r)) t)
    (0conf::restart-services-on-new-link r)
    (is (equal (list (service-instance-name info)) (0conf::responder-conflicted r)))
    (is (zerop (hash-table-count (0conf::responder-claimed-hosts r))))))

(test a-responder-given-its-own-socket-leaves-the-interface-list-alone
  "The loopback tests hand the responder a socket; reconciling that against the
live NICs would close it out from under them."
  (let ((r (make-responder)))
    (is (0conf::responder-manage-interfaces r) "on by default")
    (let ((s (handler-case (make-mdns-socket :multicast nil :port 0)
               (error (e) (skip "loopback UDP unavailable: ~A" e) nil))))
      (when s
        (unwind-protect
             (progn (start-responder r :socket s)
                    (is (not (0conf::responder-manage-interfaces r))))
          (ignore-errors (stop-responder r)))))))

(defun wait-for-threads-to-exit (responder seconds)
  "Wait up to SECONDS for RESPONDER's listeners to fall out of their loops.
A listener wakes at most once per *LISTEN-POLL-INTERVAL*, and it reads that
special in its own thread — binding it here would not reach it — so the wait is
for the threads themselves rather than for a guessed duration."
  (let ((deadline (+ (get-internal-real-time)
                     (* seconds internal-time-units-per-second))))
    (loop while (and (some #'bordeaux-threads:thread-alive-p
                           (0conf::responder-threads responder))
                     (< (get-internal-real-time) deadline))
          do (sleep 0.05))))

(test a-retired-socket-stops-its-listener
  "DROP-SOCKET unregisters before closing, so the listener sees the socket go and
falls out of its loop instead of spinning on a closed descriptor.

Only the socket creation is guarded: wrapping the assertions too would turn a
real failure into a skip, which is how this test hid a genuine one."
  (let ((s (handler-case (make-mdns-socket :multicast nil :port 0)
             (error (e) (skip "loopback UDP unavailable: ~A" e) nil))))
    (when s
      (let ((r (make-responder)))
        (unwind-protect
             (progn
               (start-responder r :socket s)
               (is (0conf::socket-active-p r s))
               (0conf::drop-socket r s)
               (is (not (0conf::socket-active-p r s)))
               (wait-for-threads-to-exit r 10)
               (0conf::prune-dead-threads r)
               (is (null (0conf::responder-threads r))))
          (setf (0conf::responder-running r) nil)
          (ignore-errors (stop-responder r)))))))

(test a-rescan-that-can-open-nothing-keeps-the-sockets-it-has
  "If every join on the new interface list fails, closing the sockets we already
have would leave the responder deaf.  Wanting sockets and getting none is the
one case where the close list is ignored."
  (is (0conf::safe-to-retire-p '() '())            "nothing wanted: closes proceed")
  (is (0conf::safe-to-retire-p '(:spec) '(:sock))  "opened something: closes proceed")
  (is (not (0conf::safe-to-retire-p '(:spec) '())) "wanted one, opened none: hold"))

(test rescanning-an-unchanged-machine-opens-nothing
  "The monitor must be idempotent: with the NICs unchanged, a rescan is a no-op
rather than a churn of close-and-reopen — and it must not queue any re-probing."
  (let* ((r (make-responder))
         (started (handler-case (progn (start-responder r) t)
                    (error (e) (skip "mDNS sockets unavailable: ~A" e) nil))))
    (when started
      (unwind-protect
           (progn
             (is (plusp (length (0conf::responder-sockets r))))
             (is (zerop (0conf::rescan-interfaces r)))
             (is (null (0conf::responder-conflicted r)))
             (is (plusp (length (0conf::responder-sockets r)))))
        (ignore-errors (stop-responder r))))))

;;; --- answering on the link a query arrived on ------------------------------

(test the-reply-goes-out-the-interface-the-query-came-in-on
  "SO_REUSEPORT means the kernel may hand a multicast datagram to any socket in
the group, so the socket a query was read from does not identify the link.  Given
the arrival index, the reply must go out the socket pinned to that link."
  (let* ((r (make-responder))
         (en0 (fake-socket "en0" :ipv4 :address #(192 168 1 5) :index 4))
         (en1 (fake-socket "en1" :ipv4 :address #(10 0 0 2) :index 7)))
    (setf (0conf::responder-sockets r) (list en0 en1))
    ;; read from en0's socket, but the kernel says it arrived on en1's link
    (is (eq en1 (0conf::socket-for-arrival r en0 7)))
    (is (eq en0 (0conf::socket-for-arrival r en1 4)))))

(test an-unknown-arrival-index-falls-back-to-the-arrival-socket
  "NIL means the kernel did not tell us, and an index we hold no socket for means
the link went away between arrival and reply.  Both keep the old behaviour."
  (let* ((r (make-responder))
         (en0 (fake-socket "en0" :ipv4 :address #(192 168 1 5) :index 4)))
    (setf (0conf::responder-sockets r) (list en0))
    (is (eq en0 (0conf::socket-for-arrival r en0 nil)))
    (is (eq en0 (0conf::socket-for-arrival r en0 99)))))

(test the-reply-socket-must-match-the-address-family
  "A v4 and a v6 socket on one NIC share an interface index; answering a v4
query on the v6 socket would send it to the wrong group entirely."
  (let* ((r (make-responder))
         (v4 (fake-socket "en0" :ipv4 :address #(192 168 1 5) :index 4))
         (v6 (fake-socket "en0" :ipv6 :index 4)))
    (setf (0conf::responder-sockets r) (list v6 v4))
    (is (eq v4 (0conf::socket-for-arrival r v4 4)))
    (is (eq v6 (0conf::socket-for-arrival r v6 4)))))

(test a-datagram-over-loopback-carries-its-peer-and-arrival-details
  "End to end through recvmsg: the datagram, the peer address and port all come
back intact.  The arrival index is whatever the kernel says — 0/absent for
looped-back traffic on Darwin — so it is only required to be absent or real,
never fabricated."
  (let ((pair (handler-case (list (make-mdns-socket :multicast nil :port 0)
                                  (make-mdns-socket :multicast nil :port 0))
                (error (e) (skip "loopback UDP unavailable: ~A" e) nil))))
    (when pair
      (destructuring-bind (a b) pair
        (unwind-protect
             (let ((bport (nth-value 1 (sb-bsd-sockets:socket-name
                                        (0conf::mdns-socket-socket b)))))
               (mdns-send a (make-array 3 :element-type '(unsigned-byte 8)
                                          :initial-element 65)
                          :host "127.0.0.1" :port bport)
               (multiple-value-bind (octets host port ifindex)
                   (mdns-recv-timeout b 2.0)
                 (is (equalp #(65 65 65) octets))
                 (is (string= "127.0.0.1" host))
                 (is (integerp port))
                 ;; NB: not '(is (or ...))' — FiveAM evaluates both branches of
                 ;; an OR to report on them, so a short-circuit that Lisp would
                 ;; take is still evaluated, and (plusp nil) would error.
                 (is (typep ifindex '(or null (integer 1 *))))))
          (close-mdns-socket a)
          (close-mdns-socket b))))))

;;; --- withdrawal must not disturb the services that are staying -------------

(defun two-services-sharing-a-host ()
  "Two registered services on one host name.  Returns (values responder http ipp)."
  (let ((r (make-responder))
        (http (make-service-info :type "_http._tcp.local" :name "Web" :host "myhost.local"
                                 :port 80 :addresses (list (parse-ipv4 "10.0.0.7"))))
        (ipp (make-service-info :type "_ipp._tcp.local" :name "Print" :host "myhost.local"
                                :port 631 :addresses (list (parse-ipv4 "10.0.0.7")))))
    (register-service r http :probe nil)
    (register-service r ipp :probe nil)
    (values r http ipp)))

(defun host-address-records (responder host)
  (count-if (lambda (x) (and (typep x 'a-record) (string-equal (rr-name x) host)))
            (0conf::responder-records responder)))

(test withdrawing-one-service-leaves-a-shared-host-intact
  "Two services on one host each contribute their own copy of its address and
NSEC records.  Withdrawing one must not take the other's copies with it, or the
service that stayed is left with an SRV pointing at a host we no longer answer
for."
  (multiple-value-bind (r http ipp) (two-services-sharing-a-host)
    (is (= 2 (host-address-records r "myhost.local")))
    (bordeaux-threads:with-lock-held ((0conf::responder-lock r))
      (0conf::withdraw-service-records r http))
    (is (equal (list ipp) (0conf::responder-services r)))
    ;; the staying service still has an address at its host ...
    (is (plusp (host-address-records r "myhost.local")))
    ;; ... its own records are untouched ...
    (is (find-if (lambda (x) (and (typep x 'srv-record)
                                  (string-equal (rr-name x) "Print._ipp._tcp.local")))
                 (0conf::responder-records r)))
    (is (find-if (lambda (x) (and (typep x 'nsec-record)
                                  (string-equal (rr-name x) "myhost.local")))
                 (0conf::responder-records r)))
    ;; ... and the withdrawn one really is gone.
    (is (not (find-if (lambda (x) (string-equal (rr-name x) "Web._http._tcp.local"))
                      (0conf::responder-records r))))
    (is (not (find-if (lambda (x) (and (typep x 'ptr-record)
                                       (string-equal (ptr-target x) "Web._http._tcp.local")))
                      (0conf::responder-records r))))))

(test withdrawing-the-last-service-on-a-host-takes-the-host-records-too
  (multiple-value-bind (r http ipp) (two-services-sharing-a-host)
    (bordeaux-threads:with-lock-held ((0conf::responder-lock r))
      (0conf::withdraw-service-records r http)
      (0conf::withdraw-service-records r ipp))
    (is (null (0conf::responder-services r)))
    (is (zerop (host-address-records r "myhost.local")))
    (is (null (0conf::responder-records r)))))

(test unregistering-clears-the-host-records-it-was-holding
  "Removing only the records at the instance name left the host's address and
NSEC behind, so the responder kept answering for a host it no longer advertised."
  (multiple-value-bind (r info) (registered-responder)
    (unregister-service r info)
    (is (null (0conf::responder-services r)))
    (is (zerop (host-address-records r "myhost.local")))
    (is (null (0conf::responder-records r)))
    (is (zerop (hash-table-count (0conf::responder-claimed-hosts r))))))

(test unregistering-one-of-two-services-keeps-the-others-host-records
  (multiple-value-bind (r http ipp) (two-services-sharing-a-host)
    (declare (ignore ipp))
    (unregister-service r http)
    (is (plusp (host-address-records r "myhost.local")))
    (is (find-if (lambda (x) (and (typep x 'srv-record)
                                  (string-equal (rr-name x) "Print._ipp._tcp.local")))
                 (0conf::responder-records r)))))

;;; --- one claim at a time, and a clean stop ---------------------------------

(test probing-is-serialized-by-the-claim-lock
  "The probe state is a single set of slots on the responder, so only one name
may be claimed at a time.  Before §9 the only prober was whichever thread called
REGISTER-SERVICE; the resolver is now a second one, and two overlapping probes
would read each other's conflict flag."
  (let* ((r (make-responder))
         (info (make-service-info :type "_x._tcp.local" :name "N" :host "h.local"
                                  :port 1 :addresses (list (parse-ipv4 "10.0.0.1"))))
         (done nil)
         (worker nil))
    (bordeaux-threads:acquire-lock (0conf::responder-claim-lock r))
    (unwind-protect
         (progn
           (setf worker (bordeaux-threads:make-thread
                         (lambda () (register-service r info) (setf done t))
                         :name "0conf-test-registrar"))
           (sleep 0.3)
           ;; Held up on the claim lock: it cannot have probed or registered.
           (is (null (0conf::responder-services r)))
           (is (null done)))
      (bordeaux-threads:release-lock (0conf::responder-claim-lock r)))
    (bordeaux-threads:join-thread worker)
    ;; NB: IS-TRUE, not IS — FiveAM's IS wants a predicate form to report on and
    ;; refuses a bare variable.
    (is-true done)
    (is (equal (list info) (0conf::responder-services r)))))

(test stopping-stops-a-conflict-resolution-resurrecting-a-service
  "STOP-RESPONDER sends the goodbyes and then joins the resolver.  A resolution
already in flight finishes afterwards, and re-registering there would put the
records back on the wire behind the goodbye — peers would hold them until TTL."
  (multiple-value-bind (r info) (registered-responder)
    (setf (0conf::responder-stopping r) t)
    (0conf::resolve-conflict r (service-instance-name info))
    (is (null (0conf::responder-services r)))
    (is (null (0conf::responder-records r)))))

(test a-responder-that-was-never-started-still-resolves-conflicts
  "STOPPING is deliberately distinct from RUNNING being NIL, which is also true
of a responder nobody has started — the unit tests drive those directly."
  (multiple-value-bind (r info) (registered-responder)
    (is (null (0conf::responder-running r)))
    (is (null (0conf::responder-stopping r)))
    (0conf::resolve-conflict r (service-instance-name info))
    (is (equal (list info) (0conf::responder-services r)))))

(test stopping-clears-the-sockets-and-threads-it-was-holding
  (let* ((r (make-responder))
         (s (handler-case (make-mdns-socket :multicast nil :port 0)
              (error (e) (skip "loopback UDP unavailable: ~A" e) nil))))
    (when s
      (start-responder r :socket s)
      (is (0conf::responder-running r))
      (stop-responder r)
      (is (0conf::responder-stopping r))
      (is (null (0conf::responder-running r)))
      (is (null (0conf::responder-sockets r)))
      (is (null (0conf::responder-threads r))))))

;;; --- probes obey the size rules too ----------------------------------------

(test a-large-probe-is-split-rather-than-sent-oversized
  "SEND-PROBE was the one sender left unchunked (§17)."
  (let* ((addresses (loop for i from 1 to 200
                          collect (parse-ipv4 (format nil "10.0.~D.~D"
                                                      (floor i 256) (mod i 256)))))
         (info (make-service-info :type "_x._tcp.local" :name "Many" :host "h.local"
                                  :port 1 :addresses addresses))
         (packets (0conf::probe-packets (service-instance-name info) info))
         (messages (mapcar #'decode-message packets)))
    (is (> (length packets) 1))
    (is (every (lambda (p) (<= (length p) 0conf::*max-message-size*)) packets))
    (is (= 1 (length (dns-message-questions (first messages)))))
    (is (every (lambda (m) (null (dns-message-questions m))) (rest messages)))
    ;; every proposed record still goes out, in the Authority section
    (is (= (length (0conf::service-info-records info))
           (loop for m in messages sum (length (dns-message-authorities m)))))))

(test an-unsendable-probe-signals-instead-of-claiming-the-name
  "MDNS-SEND drops anything over the §17 hard ceiling, and a dropped probe looks
exactly like a probe nobody answered — PROBE-CYCLE would take the silence for
success and claim a name it never probed for."
  (let* ((txt (loop for i from 0 below 40
                    collect (cons (format nil "k~2,'0D" i)
                                  (make-string 240 :initial-element #\x))))
         (info (make-service-info :type "_x._tcp.local" :name "Big" :host "h.local"
                                  :port 1 :txt txt
                                  :addresses (list (parse-ipv4 "10.0.0.1"))))
         (r (make-responder)))
    ;; the TXT alone is past the ceiling, so no split can rescue it
    (is (> (reduce #'max (mapcar #'length (0conf::probe-packets "Big._x._tcp.local" info)))
           0conf::+hard-max-message-size+))
    (signals error (0conf::send-probe r "Big._x._tcp.local" info))))

;;; --- an undecodable peer address must not break the reply path -------------

(test an-undecodable-peer-is-answered-on-the-group
  "PARSE-SOCKADDR-PEER yields NIL host and port for a sockaddr it cannot read.
That used to reach LEGACY-QUERY-P as (/= NIL 5353) — a type error the listener
swallowed, dropping the query.  With nowhere to send a unicast reply, the answer
belongs on the multicast group."
  (is (null (0conf::legacy-query-p nil)))
  (is (0conf::legacy-query-p 61244))
  (is (null (0conf::legacy-query-p +mdns-port+)))
  ;; No peer address: never unicast, whatever the query asked for.
  (is (null (0conf::unicast-reply-p t '() nil nil)))
  (is (null (0conf::unicast-reply-p nil (list (make-question :name "x" :qtype +type-any+
                                                             :unicast-response t))
                                    nil nil)))
  ;; With one, the two unicast cases still hold.
  (is (0conf::unicast-reply-p t '() "10.0.0.1" 61244))
  (is (0conf::unicast-reply-p nil (list (make-question :name "x" :qtype +type-any+
                                                       :unicast-response t))
                              "10.0.0.1" 5353))
  (is (null (0conf::unicast-reply-p nil (list (make-question :name "x" :qtype +type-any+))
                                    "10.0.0.1" 5353))))

(test conflict-timestamps-do-not-pile-up-for-a-name-we-cannot-act-on
  "A conflicting record with no service behind it queues a name the resolver can
do nothing with, so the trim that used to live only in the rate-limit check never
ran and the timestamp list grew a cons per packet forever."
  (let ((r (make-responder))
        (now (get-universal-time)))
    ;; A stale unique record with no owning service — what UNREGISTER-SERVICE
    ;; used to leave behind at the host name.
    (setf (0conf::responder-records r)
          (list (make-instance 'a-record :name "ghost.local" :cache-flush t :ttl 120
                                         :address (parse-ipv4 "10.0.0.7"))))
    (dotimes (i 50)
      (0conf::detect-record-conflicts
       r (list (peer-address-record "ghost.local" "10.0.0.99")) (- now 60)))
    (is (= 50 (length (0conf::responder-conflict-times r))))
    (is (null (0conf::conflicted-services r "ghost.local")) "nothing to resolve")
    ;; The next conflict ages all of those out, rather than adding to them.
    (0conf::detect-record-conflicts
     r (list (peer-address-record "ghost.local" "10.0.0.99")) now)
    (is (= 1 (length (0conf::responder-conflict-times r))))))

;;; --- additionals stay with the answers they support ------------------------

(test additionals-never-travel-in-a-packet-of-their-own
  "A split that landed inside the answers used to leave trailing packets holding
only additionals — ANCOUNT=0, and none of the answers they exist to support."
  (let* ((answers (loop for i from 0 below 60
                        collect (make-instance 'txt-record
                                               :name (format nil "a~D._x._tcp.local" i)
                                               :cache-flush t :ttl 120
                                               :strings (list (format nil "k=~A"
                                                                      (make-string 60 :initial-element #\x))))))
         (additionals (loop for i from 0 below 10
                            collect (make-instance 'a-record :name (format nil "h~D.local" i)
                                                             :cache-flush t :ttl 120
                                                             :address (parse-ipv4 "10.0.0.1"))))
         (packets (0conf::response-packets nil answers additionals nil))
         (messages (mapcar #'decode-message packets)))
    (is (> (length packets) 1))
    (is (every (lambda (m) (plusp (length (dns-message-answers m)))) messages))
    (is (= (length answers)
           (loop for m in messages sum (length (dns-message-answers m)))))
    (is (every (lambda (p) (<= (length p) 0conf::*max-message-size*)) packets))))

(test an-additional-rides-with-its-answer-when-there-is-room
  (let* ((answers (list (make-instance 'ptr-record :name "_x._tcp.local" :ttl 4500
                                                   :target "I._x._tcp.local")))
         (additionals (list (make-instance 'srv-record :name "I._x._tcp.local"
                                                       :cache-flush t :ttl 120
                                                       :port 1 :target "h.local")))
         (packets (0conf::response-packets nil answers additionals nil)))
    (is (= 1 (length packets)))
    (let ((m (decode-message (first packets))))
      (is (= 1 (length (dns-message-answers m))))
      (is (= 1 (length (dns-message-additionals m)))))))

(test additionals-alone-are-still-sent-when-every-answer-was-suppressed
  "SURVIVING-ANSWERS can empty the answers while additionals remain."
  (let* ((additionals (list (make-instance 'nsec-record :name "h.local" :next-name "h.local"
                                                        :cache-flush t :ttl 120
                                                        :types (list +type-a+))))
         (packets (0conf::response-packets nil '() additionals nil)))
    (is (= 1 (length packets)))
    (is (= 1 (length (dns-message-additionals (decode-message (first packets))))))))
