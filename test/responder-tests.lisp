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
