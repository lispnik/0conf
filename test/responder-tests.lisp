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
