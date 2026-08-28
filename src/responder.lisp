;;;; responder.lisp — the mDNS query/response engine (RFC 6762).
;;;;
;;;; A RESPONDER owns one or two sockets (IPv4 and, best-effort, IPv6), a
;;;; listener thread per socket, and a cache-expiry sweeper.  Incoming
;;;; *responses* feed the cache; incoming *queries* are matched against the
;;;; records we advertise and answered — with known-answer suppression, on-demand
;;;; NSEC, a randomized response delay, and legacy-unicast handling.
;;;; REGISTER-SERVICE probes the name (renaming on conflict), then announces it.

(in-package #:0conf)

(defstruct (responder (:constructor make-responder))
  (sockets '())                         ; MDNS-SOCKETs (per interface, both families)
  (threads '())                         ; one listener thread per socket
  (cache (make-cache))
  (services '())                        ; list of SERVICE-INFO we advertise
  (records '())                         ; flattened authoritative records
  (lock (bordeaux-threads:make-lock "0conf-responder"))
  (sweeper nil)
  (running nil)
  ;; Conflict detection during probing: PROBING holds the instance name we are
  ;; currently claiming (or NIL); PROBE-RECORDS are the records we propose for it
  ;; (for §8.2 tiebreaking); the listener sets CONFLICT on collision.
  (probing nil)
  (probe-records '())
  (conflict nil)
  ;; Known-answers from continuation packets (a TC'd known-answer list spilling
  ;; across datagrams), buffered per source host until the query is answered.
  (pending-ka (make-hash-table :test 'equal))
  ;; Host names we've already probed and claimed (so we probe each once even
  ;; when several services share a host).
  (claimed-hosts (make-hash-table :test 'equal))
  ;; §9 conflict resolution *after* announcing: names a peer has contradicted,
  ;; waiting for the resolver thread to put them back through probing, and the
  ;; times of recent conflicts for the §8.1 burst limit.
  (conflicted '())
  (conflict-times '())
  (resolver nil))

(defun response-p (message)
  (logbitp 15 (dns-message-flags message)))   ; QR bit

(defun responder-primary-socket (responder)
  "A socket to use as a default reply socket in code paths that don't carry one
(NIL in pure unit tests, where nothing is actually sent)."
  (first (responder-sockets responder)))

(defun broadcast (responder octets)
  "Send OCTETS out every socket (each address family's multicast group)."
  (dolist (socket (responder-sockets responder))
    (ignore-errors (mdns-send socket octets))))

(defun broadcast-packets (responder packets)
  "Send a split message (a list of encoded packets) out every socket, in order."
  (dolist (octets packets)
    (broadcast responder octets)))

;;; --- listener --------------------------------------------------------------

(defparameter *cache-sweep-interval* 1.0
  "Seconds between background cache-expiry sweeps.")

(defparameter *listen-poll-interval* 1.0
  "Max seconds a listener blocks per iteration before re-checking RUNNING.")

(defun open-interface-sockets ()
  "Open a v4 and/or v6 mDNS socket per usable interface, joined on that specific
interface.  Best-effort: a failed join on one interface never aborts the others.
Falls back to a single INADDR_ANY socket per family when enumeration yields
nothing usable (or getifaddrs is unavailable)."
  (let ((socks '()))
    (dolist (iface (ignore-errors (list-interfaces)))
      (when (net-interface-ipv4 iface)
        (let ((s (ignore-errors (make-ipv4-mdns-socket-on iface))))
          (when s (push s socks))))
      (when (net-interface-has-v6 iface)
        (let ((s (ignore-errors (make-ipv6-mdns-socket-on iface))))
          (when s (push s socks)))))
    (or (nreverse socks)
        (remove nil (list (ignore-errors (make-mdns-socket))
                          (ignore-errors (make-mdns-socket :family :ipv6)))))))

(defun start-responder (responder &key socket)
  "Open the mDNS sockets and start a listener thread per socket plus the sweeper.
SOCKET, if given, is used as the sole socket (testing over loopback, no
enumeration); otherwise one socket is opened per usable interface per family."
  (setf (responder-sockets responder) (if socket (list socket) (open-interface-sockets))
        (responder-running responder) t)
  (setf (responder-threads responder)
        (loop for s in (responder-sockets responder)
              for i from 0
              collect (let ((s s))
                        (bordeaux-threads:make-thread
                         (lambda () (responder-loop responder s))
                         :name (format nil "0conf-responder-~D" i)))))
  (setf (responder-sweeper responder)
        (bordeaux-threads:make-thread (lambda () (sweeper-loop responder))
                                      :name "0conf-sweeper"))
  (setf (responder-resolver responder)
        (bordeaux-threads:make-thread (lambda () (resolver-loop responder))
                                      :name "0conf-conflict-resolver"))
  responder)

(defun sweeper-loop (responder)
  "Periodically drop expired cache entries so removals happen on time (and memory
doesn't grow).  Wakes often enough that STOP-RESPONDER is prompt."
  (loop while (responder-running responder) do
    (sleep *cache-sweep-interval*)
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (ignore-errors (cache-expire (responder-cache responder))))
    (ignore-errors (expire-pending-ka responder))))

(defun responder-loop (responder socket)
  ;; Poll with a timeout rather than a plain blocking recv: on Linux, closing the
  ;; socket from STOP-RESPONDER does NOT wake a thread blocked in recvfrom, so a
  ;; blocking recv would hang shutdown.  A bounded wait lets the loop notice
  ;; RUNNING going false and exit promptly on every platform.
  (loop while (responder-running responder) do
    (handler-case
        (multiple-value-bind (octets host port)
            (mdns-recv-timeout socket *listen-poll-interval*)
          (when octets (handle-packet responder octets host port socket)))
      ;; A closed socket or a malformed packet must not kill the loop.
      (error () nil))))

(defun stop-responder (responder)
  ;; Best-effort: withdraw everything we advertised before going away, so peers
  ;; drop our records immediately instead of waiting for TTL expiry.
  (dolist (info (bordeaux-threads:with-lock-held ((responder-lock responder))
                  (copy-list (responder-services responder))))
    (ignore-errors (send-goodbye responder info)))
  (setf (responder-running responder) nil)
  (dolist (socket (responder-sockets responder))
    (close-mdns-socket socket))
  (dolist (thread (list* (responder-sweeper responder) (responder-resolver responder)
                         (responder-threads responder)))
    (when (and thread (bordeaux-threads:thread-alive-p thread))
      (ignore-errors (bordeaux-threads:join-thread thread))))
  responder)

;;; --- inbound ---------------------------------------------------------------

(defun continuation-packet-p (message)
  "A query carrying known-answers but no questions — the tail of a known-answer
list that a querier split across packets with the TC bit (RFC 6762 §7.2)."
  (and (null (dns-message-questions message))
       (dns-message-answers message)))

(defparameter *pending-ka-ttl* 5
  "Seconds a buffered continuation known-answer list survives without a matching
query before the sweeper evicts it (so orphaned continuations don't leak).")

(defun buffer-known-answers (responder host records &optional (now (get-universal-time)))
  "Buffer RECORDS as continuation known-answers for HOST, stamped with NOW.
Each bucket is (added-time . records)."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((entry (gethash host (responder-pending-ka responder))))
      (setf (gethash host (responder-pending-ka responder))
            (cons now (append records (cdr entry)))))))

(defun take-known-answers (responder host)
  "Return and clear the buffered continuation known-answers for HOST."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (prog1 (cdr (gethash host (responder-pending-ka responder)))
      (remhash host (responder-pending-ka responder)))))

(defun expire-pending-ka (responder &optional (now (get-universal-time)))
  "Drop buffered continuation known-answers older than *PENDING-KA-TTL* — an
orphaned continuation (no query ever followed) must not linger forever."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((ka (responder-pending-ka responder))
          (dead '()))
      (maphash (lambda (host entry)
                 (when (< (car entry) (- now *pending-ka-ttl*))
                   (push host dead)))
               ka)
      (dolist (host dead) (remhash host ka)))))

(defun handle-packet (responder octets host port &optional (socket (responder-primary-socket responder)))
  (let ((message (decode-message octets)))
    (cond
      ((response-p message)
       (let ((records (append (dns-message-answers message)
                              (dns-message-additionals message))))
         (bordeaux-threads:with-lock-held ((responder-lock responder))
           (dolist (r records) (cache-add (responder-cache responder) r)))
         (detect-conflict responder records)
         ;; §9 looks at every Resource Record Section, not just the answers.
         (detect-record-conflicts
          responder (append records (dns-message-authorities message)))))
      ;; A continuation of a TC'd known-answer list: stash it for the pending
      ;; query from this host rather than treating it as a query.
      ((continuation-packet-p message)
       (buffer-known-answers responder host (dns-message-answers message)))
      (t
       (tiebreak-probe responder message)
       (answer-query responder message host port socket)))))

(defun detect-conflict (responder records)
  "A *response* answering for the name we're probing means someone already owns
it — an unconditional conflict, so PROBE-NAME renames."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((probing (responder-probing responder)))
      (when (and probing
                 (some (lambda (r) (string-equal (rr-name r) probing)) records))
        (setf (responder-conflict responder) t)))))

;;; --- §9 conflict resolution (after announcing) -----------------------------
;;;
;;; DETECT-CONFLICT above covers the probing window only (§8.1).  Once a service
;;; is announced we are authoritative for its unique records, and §9 requires us
;;; to notice at any time that a peer is asserting something different at one of
;;; those names — and to go back to probing rather than quietly co-exist.

(defun unique-rrset (records name type class)
  "Our authoritative *unique* (cache-flush) records at NAME/TYPE/CLASS."
  (remove-if-not (lambda (r)
                   (and (rr-cache-flush r)
                        (= (rr-type r) type)
                        (= (rr-class r) class)
                        (string-equal (rr-name r) name)))
                 records))

(defun conflicting-record-p (ours incoming)
  "RFC 6762 §9: INCOMING conflicts when we hold a *unique* record at the same
name, rrtype and rrclass, and INCOMING's rdata matches none of ours there.

Records with identical rdata are never inconsistent, even from another host —
that is what lets proxies answer for us.  The comparison is against the whole
rrset, so a multi-homed host advertising two addresses at one name does not
conflict with its own second address.  A name where we hold only shared records
(a DNS-SD PTR) can never conflict."
  (let ((rrset (unique-rrset ours (rr-name incoming)
                             (rr-type incoming) (rr-class incoming))))
    (and rrset
         (notany (lambda (r) (rdata-equal r incoming)) rrset))))

(defun conflicted-services (responder name)
  "Every registered service whose unique records live at NAME: the one instance
that owns it, or all the services sharing it as their host name."
  (remove-if-not (lambda (info)
                   (or (string-equal (service-instance-name info) name)
                       (string-equal (service-info-host info) name)))
                 (responder-services responder)))

(defun detect-record-conflicts (responder records &optional (now (get-universal-time)))
  "Queue the names in RECORDS that contradict our own unique records (§9).  The
work itself is deferred to the resolver thread: probing sleeps for seconds, and
this runs on a listener that must stay free to receive.

A goodbye (ttl 0) is a withdrawal, not a competing claim, so it never counts."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (dolist (incoming records)
      (when (and (plusp (rr-ttl incoming))
                 (conflicting-record-p (responder-records responder) incoming))
        (push now (responder-conflict-times responder))
        (pushnew (rr-name incoming) (responder-conflicted responder)
                 :test #'string-equal)))))

(defparameter *conflict-burst-count* 15
  "Conflicts within *CONFLICT-BURST-WINDOW* seconds that trip the §8.1 limit.")

(defparameter *conflict-burst-window* 10
  "Width in seconds of the window the §8.1 conflict burst limit counts over.")

(defparameter *conflict-burst-delay* 5.0
  "Seconds to wait before each further probe attempt once the burst limit trips
— RFC 6762 §8.1: \"If fifteen conflicts occur within any ten-second period, then
the host MUST wait at least five seconds before each successive additional probe
attempt.\"  This is the backstop against a buggy or hostile peer goading us into
flooding the link with probes.")

(defun conflict-rate-limited-p (responder &optional (now (get-universal-time)))
  "True when *CONFLICT-BURST-COUNT* conflicts have landed within the last
*CONFLICT-BURST-WINDOW* seconds.  Trims the window as it goes, so the timestamp
list cannot grow without bound."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((recent (remove-if (lambda (ts) (< ts (- now *conflict-burst-window*)))
                             (responder-conflict-times responder))))
      (setf (responder-conflict-times responder) recent)
      (>= (length recent) *conflict-burst-count*))))

(defun take-conflicted (responder)
  "Return and clear the queued conflicted names."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (prog1 (responder-conflicted responder)
      (setf (responder-conflicted responder) '()))))

(defun withdraw-service-records (responder info)
  "Drop INFO's records from our authoritative set.  Caller holds the lock."
  (let ((instance (service-instance-name info)))
    (setf (responder-records responder)
          (set-difference (responder-records responder) (service-info-records info)
                          :test (lambda (a b)
                                  (and (string-equal (rr-name a) (rr-name b))
                                       (= (rr-type a) (rr-type b))
                                       (rdata-equal a b))))
          (responder-services responder)
          (remove info (responder-services responder)))
    ;; PTRs point *at* the instance rather than living at its name.
    (setf (responder-records responder)
          (remove-if (lambda (r) (and (typep r 'ptr-record)
                                      (string-equal (ptr-target r) instance)))
                     (responder-records responder)))))

(defun resolve-conflict (responder name)
  "The §9 corrective action for NAME: withdraw what we hold there and put every
service that depends on the name back through §8 probing, which renames us if
the probe shows we lost.  A host name can back several services, so each of
them is re-registered; they converge on the same new host name because each
re-probes the old one and loses again."
  (let ((affected (bordeaux-threads:with-lock-held ((responder-lock responder))
                    (conflicted-services responder name))))
    (when affected
      (bordeaux-threads:with-lock-held ((responder-lock responder))
        (dolist (info affected)
          (withdraw-service-records responder info))
        ;; The host must be probed afresh, so forget that we ever claimed it.
        (remhash name (responder-claimed-hosts responder)))
      (when (conflict-rate-limited-p responder)
        (sleep *conflict-burst-delay*))
      (dolist (info affected)
        (ignore-errors (register-service responder info))))))

(defparameter *conflict-poll-interval* 0.25
  "Seconds the §9 resolver sleeps between checks of the conflicted-name queue.")

(defun resolver-loop (responder)
  "Runs the §9 corrective action off the listener threads."
  (loop while (responder-running responder) do
    (sleep *conflict-poll-interval*)
    (dolist (name (take-conflicted responder))
      (ignore-errors (resolve-conflict responder name)))))

;;; --- §8.2 lexicographic tiebreaking ---------------------------------------

(defun compare-octets (a b)
  "Lexicographic comparison of two octet vectors: -1, 0, or 1 (shorter is
earlier when one is a prefix of the other)."
  (let ((n (min (length a) (length b))))
    (dotimes (i n)
      (let ((x (aref a i)) (y (aref b i)))
        (cond ((< x y) (return-from compare-octets -1))
              ((> x y) (return-from compare-octets 1)))))
    (signum (- (length a) (length b)))))

(defun compare-records (a b)
  "RFC 6762 §8.2.1 pairwise record comparison: class (sans cache-flush bit),
then type, then a raw byte comparison of the uncompressed rdata."
  (let ((ca (logand (rr-class a) (lognot +cache-flush-bit+)))
        (cb (logand (rr-class b) (lognot +cache-flush-bit+))))
    (cond ((/= ca cb) (signum (- ca cb)))
          ((/= (rr-type a) (rr-type b)) (signum (- (rr-type a) (rr-type b))))
          ;; RDATA-OCTETS uses a fresh writer, so embedded names come out
          ;; uncompressed — exactly the canonical form §8.2 wants.
          (t (compare-octets (rdata-octets a) (rdata-octets b))))))

(defun compare-record-sets (ours theirs)
  "Compare two record sets in canonical order, from OURS's perspective.
Returns :WIN, :LOSE, or :TIE (RFC 6762 §8.2)."
  (flet ((canonical (set)
           (sort (copy-list set) (lambda (x y) (minusp (compare-records x y))))))
    (let ((a (canonical ours))
          (b (canonical theirs)))
      (loop for ra in a for rb in b
            for c = (compare-records ra rb)
            unless (zerop c)
              do (return-from compare-record-sets (if (plusp c) :win :lose)))
      ;; identical prefix: the set with more records is lexicographically later
      (case (signum (- (length a) (length b)))
        (1 :win) (-1 :lose) (0 :tie)))))

(defun tiebreak-probe (responder message)
  "A simultaneous prober's *query* carries its proposed records in the Authority
section.  If we're probing the same name and their set is lexicographically
later, we lose and must rename (RFC 6762 §8.2).  A tie (identical data) is not a
conflict."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((probing (responder-probing responder)))
      (when (and probing
                 (some (lambda (q) (string-equal (question-name q) probing))
                       (dns-message-questions message)))
        (flet ((at-name (records)
                 (remove-if-not (lambda (r) (string-equal (rr-name r) probing))
                                records)))
          (let ((theirs (at-name (dns-message-authorities message)))
                (ours (at-name (responder-probe-records responder))))
            (when (and theirs
                       (eq :lose (compare-record-sets ours theirs)))
              (setf (responder-conflict responder) t))))))))

;;; --- building a response ---------------------------------------------------

(defun record-answers-question-p (record question)
  (and (string-equal (rr-name record) (question-name question))
       (or (= (question-qtype question) +type-any+)
           (= (question-qtype question) (rr-type record)))
       (= (question-qclass question) (rr-class record))))

(defun known-answer-p (record known-answers)
  "True if the querier already listed RECORD (with at least half its ttl left),
per RFC 6762 known-answer suppression."
  (some (lambda (ka)
          (and (= (rr-type ka) (rr-type record))
               (string-equal (rr-name ka) (rr-name record))
               (rdata-equal ka record)
               (>= (rr-ttl ka) (floor (rr-ttl record) 2))))
        known-answers))

(defparameter *response-delay* t
  "When true, multicast responses are delayed a random 20-120ms (RFC 6762 §6),
which spreads simultaneous responders and lets answers aggregate.  Bound to NIL
in tests.")

(defun own-name-p (records name)
  (some (lambda (r) (string-equal (rr-name r) name)) records))

(defun nsec-at (records name)
  (find-if (lambda (r) (and (typep r 'nsec-record)
                            (string-equal (rr-name r) name)))
           records))

(defun responder-records-snapshot (responder)
  "A locked copy of our authoritative records — safe to read from the listener
thread while REGISTER/UNREGISTER-SERVICE mutate the list."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (copy-list (responder-records responder))))

(defun build-response (responder message
                       &optional (known-answers (dns-message-answers message)))
  "Compute the response to MESSAGE against our records, as
(values answers additionals).  Answers to *all* the query's questions are
aggregated into one response (RFC 6762 §7.4).  KNOWN-ANSWERS is the querier's
known-answer list to suppress against — defaulting to the message's own, but the
caller may pass a list merged across continuation packets (§7.2).  Pure apart
from a locked snapshot of the record list, so it is unit-testable.

Includes on-demand NSEC (RFC 6762 §6.1): a positive answer carries our NSEC for
that name in Additional so the querier learns the full type set; a specific-type
query for a name we own but lack that type is answered with the NSEC as a
negative response."
  (let ((records (responder-records-snapshot responder))
        (answers '())
        (additionals '()))
    (dolist (question (dns-message-questions message))
      (let ((matched (remove-if-not
                      (lambda (r) (and (record-answers-question-p r question)
                                       (not (known-answer-p r known-answers))))
                      records)))
        (cond
          (matched
           (dolist (r matched) (pushnew r answers))
           (let ((nsec (nsec-at records (question-name question))))
             (when (and nsec (not (member nsec answers)))
               (pushnew nsec additionals))))
          ;; Negative answer: we own the name but not the requested type.
          ((and (/= (question-qtype question) +type-any+)
                (own-name-p records (question-name question)))
           (let ((nsec (nsec-at records (question-name question))))
             (when (and nsec (not (member (question-qtype question) (nsec-types nsec))))
               (pushnew nsec answers)))))))
    (values (nreverse answers) (nreverse additionals))))

(defun legacy-query-p (port)
  "A query from a source port other than 5353 is a one-shot legacy resolver
(RFC 6762 §6.7): reply unicast, echo the id, repeat the question, cap TTLs."
  (/= port +mdns-port+))

(defparameter *legacy-max-ttl* 10
  "Cap (seconds) on TTLs in legacy unicast responses (RFC 6762 §6.7).")

(defun make-response-message (query answers additionals legacy)
  (flet ((cap (records)
           (if legacy
               (mapcar (lambda (r) (clone-record r :ttl (min (rr-ttl r) *legacy-max-ttl*)))
                       records)
               records)))
    (make-dns-message
     :id (if legacy (dns-message-id query) 0)
     :flags +flag-response+
     :questions (if legacy (dns-message-questions query) '())
     :answers (cap answers)
     :additionals (cap additionals))))

(defun response-packets (query answers additionals legacy)
  "Encode a response as one or more packets, none over *MAX-MESSAGE-SIZE*
(RFC 6762 §17).  Answers and additionals are distributed together in order, each
packet carrying whichever of them landed in it; a legacy unicast reply repeats
the question in every packet, so each one stands alone as an answer to that
query.  Returns a list of octet vectors."
  (flet ((message-for (tagged)
           (make-response-message
            query
            (loop for (tag . r) in tagged when (eq tag :answer) collect r)
            (loop for (tag . r) in tagged when (eq tag :additional) collect r)
            legacy)))
    (let ((tagged (append (mapcar (lambda (r) (cons :answer r)) answers)
                          (mapcar (lambda (r) (cons :additional r)) additionals))))
      (mapcar (lambda (group) (encode-message (message-for group)))
              (chunk-records tagged *max-message-size*
                             (lambda (group first)
                               (declare (ignore first))
                               (message-for group)))))))

(defun surviving-answers (answers cache already-matched)
  "Drop answers a *peer* multicast during our response delay: an answer now in
the cache that wasn't already there when we scheduled the response (RFC 6762 §6
duplicate-response suppression).  ALREADY-MATCHED are the answers that had a
cache match up front (e.g. our own looped-back records), which we keep."
  (remove-if (lambda (r)
               (and (not (member r already-matched))
                    (cache-has-answer-p cache r)))
             answers))

(defun answer-query (responder message host port &optional (socket (responder-primary-socket responder)))
  (multiple-value-bind (answers additionals) (build-response responder message)
    (when (or answers additionals)
      (let* ((questions (dns-message-questions message))
             (legacy (legacy-query-p port))
             (unicast (or legacy
                          (and questions
                               (question-unicast-response (first questions))))))
        (cond
          (unicast
           ;; Immediate, no aggregation delay or suppression.
           (dolist (packet (response-packets message answers additionals legacy))
             (mdns-send socket packet :host host :port port)))
          (t
           ;; Multicast: delay (longer if the query was truncated), then apply
           ;; known-answer suppression against continuation packets that arrived
           ;; meanwhile, and drop answers a peer already sent.
           (let ((already (remove-if-not
                           (lambda (r) (cache-has-answer-p (responder-cache responder) r))
                           answers)))
             (when *response-delay*
               (sleep (+ 0.02 (random 0.1)
                         (if (message-truncated-p message) 0.4 0.0))))
             (let ((known (append (dns-message-answers message)
                                  (take-known-answers responder host))))
               (multiple-value-bind (final-answers final-additionals)
                   (build-response responder message known)
                 (let ((surviving (surviving-answers final-answers
                                                     (responder-cache responder) already)))
                   (when (or surviving final-additionals)
                     (dolist (packet (response-packets message surviving
                                                       final-additionals nil))
                       (mdns-send socket packet)))))))))))))

;;; --- outbound: register / announce / goodbye -------------------------------

(defun next-instance-name (name)
  "Bump a service-instance label per RFC 6762 §9:
\"Name\" -> \"Name (2)\", \"Name (2)\" -> \"Name (3)\"."
  (let ((close (1- (length name))))
    (if (and (plusp (length name)) (char= (char name close) #\)))
        (let ((open (position #\( name :from-end t :end close)))
          (if (and open
                   (> close (1+ open))                          ; at least one digit
                   (every #'digit-char-p (subseq name (1+ open) close))
                   (>= open 1) (char= (char name (1- open)) #\Space))
              (format nil "~A(~D)"
                      (subseq name 0 open)                       ; keeps the trailing space
                      (1+ (parse-integer name :start (1+ open) :end close)))
              (format nil "~A (2)" name)))
        (format nil "~A (2)" name))))

(defun send-probe (responder name info)
  "One probe: a unicast-response query for NAME with our proposed records in the
Authority section (for tiebreaking), per RFC 6762 §8.1."
  (broadcast responder
             (encode-message
              (make-dns-message
               :questions (list (make-question :name name :qtype +type-any+
                                               :unicast-response t))
               :authorities (service-info-records info)))))

(defun bump-hostname-label (label)
  "\"myhost\" -> \"myhost-2\", \"myhost-2\" -> \"myhost-3\" (RFC 6762 §9 hostnames)."
  (let ((dash (position #\- label :from-end t)))
    (if (and dash (< (1+ dash) (length label))
             (every #'digit-char-p (subseq label (1+ dash))))
        (format nil "~A~D" (subseq label 0 (1+ dash))
                (1+ (parse-integer label :start (1+ dash))))
        (format nil "~A-2" label))))

(defun next-host-name (host)
  "Bump the first label of a host name: \"myhost.local\" -> \"myhost-2.local\"."
  (let ((dot (position #\. host)))
    (if dot
        (format nil "~A~A" (bump-hostname-label (subseq host 0 dot)) (subseq host dot))
        (bump-hostname-label host))))

(defparameter *probe-conflict-backoff* 1.0
  "Seconds to wait after a probe conflict before probing a new name (§8.1).")

(defun probe-cycle (responder name info)
  "Probe NAME three times (250ms apart), watching for a conflict.  Returns T if a
conflict was detected during the window."
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (setf (responder-conflict responder) nil
          (responder-probing responder) name
          (responder-probe-records responder) (service-info-records info)))
  (unwind-protect
       (dotimes (i 3)
         (send-probe responder name info)
         (sleep 0.25)
         (when (responder-conflict responder) (return)))
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (setf (responder-probing responder) nil
            (responder-probe-records responder) '())))
  (responder-conflict responder))

(defun claim-name (responder info name-fn rename-fn &key (max-attempts 20))
  "Probe (funcall NAME-FN INFO); on conflict wait, RENAME-FN (mutating INFO), and
retry until the name is free (RFC 6762 §8/§9).  Returns INFO."
  (dotimes (attempt max-attempts
                    (error "0conf: no free name for ~S after ~D attempts"
                           (funcall name-fn info) max-attempts))
    (if (probe-cycle responder (funcall name-fn info) info)
        (progn (sleep *probe-conflict-backoff*) (funcall rename-fn info))
        (return info))))

(defparameter *announce-interval* 1.0
  "Seconds between the two announcements (RFC 6762 §8.3).  Bound to 0 in tests.")

(defun announce (responder records)
  "Unsolicited responses so listeners learn the records immediately.
RFC 6762 §8.3 asks for at least two, at least 1s apart.  A record set too big
for one datagram goes out as several (§17)."
  (let ((packets (response-packets nil records '() nil)))
    (dotimes (i 2)
      (broadcast-packets responder packets)
      (sleep *announce-interval*))))

(defun register-service (responder info &key (probe t))
  "Advertise INFO.  Probes the instance name AND the host name (renaming each on
conflict, RFC 6762 §8/§9), then announces its record set.  Records are built
*after* probing so any rename is reflected."
  (when probe
    ;; Claim the unique instance name.
    (claim-name responder info #'service-instance-name
                (lambda (i) (setf (service-info-name i)
                                  (next-instance-name (service-info-name i)))))
    ;; Claim the host name, once per host (many services can share it).
    (unless (gethash (service-info-host info) (responder-claimed-hosts responder))
      (claim-name responder info #'service-info-host
                  (lambda (i) (setf (service-info-host i)
                                    (next-host-name (service-info-host i)))))
      (setf (gethash (service-info-host info) (responder-claimed-hosts responder)) t)))
  (let ((records (service-info-records info)))
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (push info (responder-services responder))
      (setf (responder-records responder)
            (append records (responder-records responder))))
    (announce responder records)
    info))

(defun update-service-txt (responder info new-txt)
  "Change a registered service's TXT to NEW-TXT (an alist) and re-announce the new
record (RFC 6762 §8.4): the cache-flush TXT supersedes the old one in listeners'
caches.  INFO must already be registered."
  (setf (service-info-txt info) new-txt)
  (let ((record (make-instance 'txt-record
                               :name (service-instance-name info)
                               :cache-flush t :ttl *default-other-ttl*
                               :strings (txt-alist->strings new-txt))))
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (setf (responder-records responder)
            (cons record
                  (remove-if (lambda (r)
                               (and (typep r 'txt-record)
                                    (string-equal (rr-name r) (service-instance-name info))))
                             (responder-records responder)))))
    (announce responder (list record))
    info))

(defun send-goodbye (responder info)
  "Announce INFO's records with ttl 0 so listeners drop them at once (RFC 6762
§10.1).  Builds a fresh record set, so it never mutates our live records."
  (let ((goodbye (service-info-records info)))
    (dolist (r goodbye) (setf (rr-ttl r) 0))
    (broadcast-packets responder (response-packets nil goodbye '() nil))))

(defun unregister-service (responder info)
  "Send a goodbye and drop INFO's records."
  (send-goodbye responder info)
  (let ((instance (service-instance-name info)))
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (setf (responder-services responder)
            (remove info (responder-services responder)))
      (setf (responder-records responder)
            (remove-if (lambda (r)
                         (or (string-equal (rr-name r) instance)
                             (and (typep r 'ptr-record)
                                  (string-equal (ptr-target r) instance))))
                       (responder-records responder)))))
  info)
