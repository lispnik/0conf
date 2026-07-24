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
  socket                                ; IPv4 socket
  socket6                               ; IPv6 socket (may be NIL)
  (cache (make-cache))
  (services '())                        ; list of SERVICE-INFO we advertise
  (records '())                         ; flattened authoritative records
  (lock (bordeaux-threads:make-lock "0conf-responder"))
  (thread nil)                          ; v4 listener
  (thread6 nil)                         ; v6 listener
  (sweeper nil)
  (running nil)
  ;; Conflict detection during probing: PROBING holds the instance name we are
  ;; currently claiming (or NIL); PROBE-RECORDS are the records we propose for it
  ;; (for §8.2 tiebreaking); the listener sets CONFLICT on collision.
  (probing nil)
  (probe-records '())
  (conflict nil))

(defun response-p (message)
  (logbitp 15 (dns-message-flags message)))   ; QR bit

(defun responder-sockets (responder)
  "The live sockets (v4, and v6 if present)."
  (remove nil (list (responder-socket responder) (responder-socket6 responder))))

(defun broadcast (responder octets)
  "Send OCTETS out every socket (each address family's multicast group)."
  (dolist (socket (responder-sockets responder))
    (ignore-errors (mdns-send socket octets))))

;;; --- listener --------------------------------------------------------------

(defparameter *cache-sweep-interval* 1.0
  "Seconds between background cache-expiry sweeps.")

(defparameter *listen-poll-interval* 1.0
  "Max seconds a listener blocks per iteration before re-checking RUNNING.")

(defun start-responder (responder &key socket)
  "Open the mDNS socket(s) and start a listener per socket plus the sweeper.
SOCKET, if given, is used as the sole (IPv4) socket for testing over loopback;
otherwise a v4 socket is opened and a v6 socket is attempted best-effort."
  (setf (responder-socket responder) (or socket (make-mdns-socket))
        (responder-socket6 responder) (unless socket
                                        (ignore-errors (make-mdns-socket :family :ipv6)))
        (responder-running responder) t)
  (setf (responder-thread responder)
        (bordeaux-threads:make-thread
         (lambda () (responder-loop responder (responder-socket responder)))
         :name "0conf-responder-v4"))
  (when (responder-socket6 responder)
    (setf (responder-thread6 responder)
          (bordeaux-threads:make-thread
           (lambda () (responder-loop responder (responder-socket6 responder)))
           :name "0conf-responder-v6")))
  (setf (responder-sweeper responder)
        (bordeaux-threads:make-thread (lambda () (sweeper-loop responder))
                                      :name "0conf-sweeper"))
  responder)

(defun sweeper-loop (responder)
  "Periodically drop expired cache entries so removals happen on time (and memory
doesn't grow).  Wakes often enough that STOP-RESPONDER is prompt."
  (loop while (responder-running responder) do
    (sleep *cache-sweep-interval*)
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (ignore-errors (cache-expire (responder-cache responder))))))

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
  (dolist (thread (list (responder-thread responder) (responder-thread6 responder)
                        (responder-sweeper responder)))
    (when (and thread (bordeaux-threads:thread-alive-p thread))
      (ignore-errors (bordeaux-threads:join-thread thread))))
  responder)

;;; --- inbound ---------------------------------------------------------------

(defun handle-packet (responder octets host port &optional (socket (responder-socket responder)))
  (let ((message (decode-message octets)))
    (if (response-p message)
        (let ((records (append (dns-message-answers message)
                               (dns-message-additionals message))))
          (bordeaux-threads:with-lock-held ((responder-lock responder))
            (dolist (r records) (cache-add (responder-cache responder) r)))
          (detect-conflict responder records))
        (progn
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

(defun build-response (responder message)
  "Compute the response to MESSAGE against our records, as
(values answers additionals).  Answers to *all* the query's questions are
aggregated into one response (RFC 6762 §7.4).  Pure apart from a locked snapshot
of the record list, so it is unit-testable.

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
                                       (not (known-answer-p
                                             r (dns-message-answers message)))))
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

(defun answer-query (responder message host port &optional (socket (responder-socket responder)))
  (multiple-value-bind (answers additionals) (build-response responder message)
    (when (or answers additionals)
      (let* ((questions (dns-message-questions message))
             (legacy (legacy-query-p port))
             (unicast (or legacy
                          (and questions
                               (question-unicast-response (first questions)))))
             (reply (encode-message
                     (make-response-message message answers additionals legacy))))
        (cond
          (unicast
           (mdns-send socket reply :host host :port port))
          (t
           (when *response-delay*
             ;; A truncated query means more known-answers are coming; wait a bit
             ;; longer to collect them before answering (RFC 6762 §7.2).
             (sleep (+ 0.02 (random 0.1)
                       (if (message-truncated-p message) 0.4 0.0))))
           (mdns-send socket reply)))))))

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

(defparameter *probe-conflict-backoff* 1.0
  "Seconds to wait after a probe conflict before probing a new name (§8.1).")

(defun probe-name (responder info &key (max-attempts 20))
  "Probe INFO's instance name three times (250ms apart).  On a detected conflict,
wait a second, rename via NEXT-INSTANCE-NAME (mutating INFO), and probe again.
Returns INFO once a name is successfully claimed."
  (dotimes (attempt max-attempts
                    (error "0conf: no free name for ~S after ~D attempts"
                           (service-info-name info) max-attempts))
    (let ((name (service-instance-name info))
          (records (service-info-records info)))
      (bordeaux-threads:with-lock-held ((responder-lock responder))
        (setf (responder-conflict responder) nil
              (responder-probing responder) name
              (responder-probe-records responder) records))
      (unwind-protect
           (dotimes (i 3)
             (send-probe responder name info)
             (sleep 0.25)
             (when (responder-conflict responder) (return)))
        (bordeaux-threads:with-lock-held ((responder-lock responder))
          (setf (responder-probing responder) nil
                (responder-probe-records responder) '())))
      (if (responder-conflict responder)
          (progn
            (sleep *probe-conflict-backoff*)     ; rate-limit re-probing (§8.1)
            (setf (service-info-name info)
                  (next-instance-name (service-info-name info))))
          (return info)))))

(defun announce (responder records)
  "Unsolicited responses so listeners learn the records immediately.
RFC 6762 §8.3 asks for at least two, at least 1s apart."
  (let ((message (encode-message
                  (make-dns-message :flags +flag-response+ :answers records))))
    (dotimes (i 2)
      (broadcast responder message)
      (sleep 1))))

(defun register-service (responder info &key (probe t))
  "Advertise INFO.  Probes the instance name (renaming on conflict), then
announces its record set.  Records are built *after* probing so a rename is
reflected."
  (when probe (probe-name responder info))     ; may rename INFO in place
  (let ((records (service-info-records info)))
    (bordeaux-threads:with-lock-held ((responder-lock responder))
      (push info (responder-services responder))
      (setf (responder-records responder)
            (append records (responder-records responder))))
    (announce responder records)
    info))

(defun send-goodbye (responder info)
  "Announce INFO's records with ttl 0 so listeners drop them at once (RFC 6762
§10.1).  Builds a fresh record set, so it never mutates our live records."
  (let ((goodbye (service-info-records info)))
    (dolist (r goodbye) (setf (rr-ttl r) 0))
    (broadcast responder
               (encode-message
                (make-dns-message :flags +flag-response+ :answers goodbye)))))

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
