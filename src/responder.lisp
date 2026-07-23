;;;; responder.lisp — the mDNS query/response engine (RFC 6762).
;;;;
;;;; A RESPONDER owns the socket and a listener thread.  Incoming *responses*
;;;; feed the cache; incoming *queries* are matched against the records we've
;;;; been asked to advertise, and answered (with known-answer suppression).
;;;; REGISTER-SERVICE probes the name, then announces it.
;;;;
;;;; Pragmatic scope for now: probing sends the queries but does not yet rename
;;;; on conflict (flagged below); the response delay is fixed rather than the
;;;; RFC's randomized 20-120ms.  The wire behaviour is otherwise conformant.

(in-package #:0conf)

(defstruct (responder (:constructor make-responder))
  socket
  (cache (make-cache))
  (services '())                        ; list of SERVICE-INFO we advertise
  (records '())                         ; flattened authoritative records
  (lock (bordeaux-threads:make-lock "0conf-responder"))
  (thread nil)
  (running nil)
  ;; Conflict detection during probing: PROBING holds the instance name we are
  ;; currently claiming (or NIL), and the listener sets CONFLICT if it sees
  ;; someone else answering for that name.
  (probing nil)
  (conflict nil))

(defun response-p (message)
  (logbitp 15 (dns-message-flags message)))   ; QR bit

;;; --- listener --------------------------------------------------------------

(defun start-responder (responder)
  (setf (responder-socket responder) (make-mdns-socket)
        (responder-running responder) t
        (responder-thread responder)
        (bordeaux-threads:make-thread (lambda () (responder-loop responder))
                                      :name "0conf-responder"))
  responder)

(defun responder-loop (responder)
  (loop while (responder-running responder) do
    (handler-case
        (multiple-value-bind (octets host port) (mdns-recv (responder-socket responder))
          (when octets (handle-packet responder octets host port)))
      ;; A closed socket (from STOP-RESPONDER) or a malformed packet must not
      ;; kill the loop.
      (error () nil))))

(defun stop-responder (responder)
  (setf (responder-running responder) nil)
  (when (responder-socket responder)
    (close-mdns-socket (responder-socket responder)))
  (let ((thread (responder-thread responder)))
    (when (and thread (bordeaux-threads:thread-alive-p thread))
      (ignore-errors (bordeaux-threads:join-thread thread))))
  responder)

;;; --- inbound ---------------------------------------------------------------

(defun handle-packet (responder octets host port)
  (let ((message (decode-message octets)))
    (if (response-p message)
        (let ((records (append (dns-message-answers message)
                               (dns-message-additionals message))))
          (dolist (r records) (cache-add (responder-cache responder) r))
          (detect-conflict responder records))
        (answer-query responder message host port))))

(defun detect-conflict (responder records)
  "If we are probing a name and someone else authoritatively answers for it,
flag a conflict so PROBE-NAME renames.  (Simultaneous-prober lexicographic
tiebreaking per RFC 6762 §8.2 is a TODO; this handles an already-claimed name.)"
  (bordeaux-threads:with-lock-held ((responder-lock responder))
    (let ((probing (responder-probing responder)))
      (when (and probing
                 (some (lambda (r) (string-equal (rr-name r) probing)) records))
        (setf (responder-conflict responder) t)))))

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

(defun answer-query (responder message host port)
  (let ((answers '()))
    (dolist (question (dns-message-questions message))
      (dolist (record (responder-records responder))
        (when (and (record-answers-question-p record question)
                   (not (known-answer-p record (dns-message-answers message))))
          (pushnew record answers))))
    (when answers
      (let ((reply (encode-message
                    (make-dns-message :flags +flag-response+
                                      :answers (nreverse answers)))))
        (if (and (dns-message-questions message)
                 (question-unicast-response (first (dns-message-questions message))))
            (mdns-send (responder-socket responder) reply :host host :port port)
            (mdns-send (responder-socket responder) reply))))))

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
  (mdns-send (responder-socket responder)
             (encode-message
              (make-dns-message
               :questions (list (make-question :name name :qtype +type-any+
                                               :unicast-response t))
               :authorities (service-info-records info)))))

(defun probe-name (responder info &key (max-attempts 20))
  "Probe INFO's instance name three times (250ms apart).  On a detected conflict,
rename via NEXT-INSTANCE-NAME (mutating INFO) and probe again.  Returns INFO once
a name is successfully claimed."
  (dotimes (attempt max-attempts
                    (error "0conf: no free name for ~S after ~D attempts"
                           (service-info-name info) max-attempts))
    (let ((name (service-instance-name info)))
      (bordeaux-threads:with-lock-held ((responder-lock responder))
        (setf (responder-conflict responder) nil
              (responder-probing responder) name))
      (unwind-protect
           (dotimes (i 3)
             (send-probe responder name info)
             (sleep 0.25)
             (when (responder-conflict responder) (return)))
        (bordeaux-threads:with-lock-held ((responder-lock responder))
          (setf (responder-probing responder) nil)))
      (if (responder-conflict responder)
          (setf (service-info-name info)
                (next-instance-name (service-info-name info)))
          (return info)))))

(defun announce (responder records)
  "Unsolicited responses so listeners learn the records immediately.
RFC 6762 §8.3 asks for at least two, at least 1s apart."
  (let ((message (encode-message
                  (make-dns-message :flags +flag-response+ :answers records))))
    (dotimes (i 2)
      (mdns-send (responder-socket responder) message)
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

(defun unregister-service (responder info)
  "Send goodbye packets (ttl 0) and drop INFO's records."
  (let ((goodbye (service-info-records info)))
    (dolist (r goodbye) (setf (rr-ttl r) 0))
    (mdns-send (responder-socket responder)
               (encode-message
                (make-dns-message :flags +flag-response+ :answers goodbye))))
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
