;;;; message.lisp — the DNS message: 12-byte header + four record sections.
;;;; mDNS reuses the classic DNS wire format verbatim, so this layer is shared
;;;; between queries and responses.

(in-package #:0conf)

(defstruct (question (:constructor make-question))
  (name "" :type string)
  (qtype +type-a+)
  (qclass +class-in+)
  ;; mDNS: top bit of qclass = "please answer via unicast".
  (unicast-response nil))

(defstruct (dns-message (:constructor make-dns-message))
  (id 0)
  (flags 0)                 ; e.g. +flag-response+ for an authoritative answer
  (questions '())
  (answers '())
  (authorities '())
  (additionals '()))

(defun message-truncated-p (message)
  "The TC (truncation) bit — set by a querier whose known-answer list spills into
follow-up packets (RFC 6762 §7.2)."
  (logbitp 9 (dns-message-flags message)))

(defun write-question (writer question)
  (write-name writer (question-name question))
  (write-u16 writer (question-qtype question))
  (write-u16 writer (logior (question-qclass question)
                            (if (question-unicast-response question)
                                +cache-flush-bit+ 0))))

(defun read-question (reader)
  (let* ((name (read-name reader))
         (qtype (read-u16 reader))
         (raw-class (read-u16 reader)))
    (make-question :name name
                   :qtype qtype
                   :qclass (logand raw-class (lognot +cache-flush-bit+))
                   :unicast-response (logtest raw-class +cache-flush-bit+))))

(defun encode-message (message)
  "Serialize a DNS-MESSAGE to a fresh simple octet vector."
  (let ((w (make-writer)))
    (write-u16 w (dns-message-id message))
    (write-u16 w (dns-message-flags message))
    (write-u16 w (length (dns-message-questions message)))
    (write-u16 w (length (dns-message-answers message)))
    (write-u16 w (length (dns-message-authorities message)))
    (write-u16 w (length (dns-message-additionals message)))
    (dolist (q (dns-message-questions message))   (write-question w q))
    (dolist (r (dns-message-answers message))     (write-record w r))
    (dolist (r (dns-message-authorities message)) (write-record w r))
    (dolist (r (dns-message-additionals message)) (write-record w r))
    (writer-result w)))

(defun decode-message (octets)
  "Parse OCTETS (any octet vector) into a DNS-MESSAGE."
  (let* ((r  (make-reader (ensure-simple-octets octets)))
         (id (read-u16 r))
         (flags (read-u16 r))
         (qd (read-u16 r))
         (an (read-u16 r))
         (ns (read-u16 r))
         (ar (read-u16 r)))
    (make-dns-message
     :id id
     :flags flags
     :questions   (loop repeat qd collect (read-question r))
     :answers     (loop repeat an collect (read-record r))
     :authorities (loop repeat ns collect (read-record r))
     :additionals (loop repeat ar collect (read-record r)))))

;;; --- packet size discipline (RFC 6762 §17 / §7.2) --------------------------

(defun chunk-records (records budget make-message)
  "Split RECORDS into consecutive groups, each of which encodes to at most BUDGET
octets.  MAKE-MESSAGE is called with (group first-group-p) and returns the
DNS-MESSAGE that group would be sent as.

Each candidate group is encoded to measure it rather than summing per-record
sizes: name compression makes a record's encoded length depend on what precedes
it in the packet, so the sum would be wrong (and always an overestimate).

A record too large to share a packet with anything gets a group of its own —
RFC 6762 §17 allows a single oversized record to go alone in a fragmented
datagram, and requires that such a packet hold nothing else.  Returns NIL for no
records, so callers that must still send something (a query with no known
answers) can special-case it."
  (let ((groups '())
        (pending records)
        (first t))
    (loop while pending do
      (let ((group '()))
        (loop while pending do
          (let* ((candidate (append group (list (first pending))))
                 (size (length (encode-message (funcall make-message candidate first)))))
            ;; The first record in a group is taken unconditionally: something
            ;; must go in, even if it alone busts the budget.
            (if (or (null group) (<= size budget))
                (setf group candidate
                      pending (rest pending))
                (return))))
        (push group groups)
        (setf first nil)))
    (nreverse groups)))

(defun query-message (questions known-answers &optional truncated)
  "A query carrying KNOWN-ANSWERS.  TRUNCATED sets the TC bit, which on an mDNS
query means \"more known answers follow in the next packet\" (RFC 6762 §7.2)."
  (make-dns-message :flags (if truncated +flag-truncated+ 0)
                    :questions questions
                    :answers known-answers))

(defun known-answer-query-packets (questions known-answers
                                   &optional (budget *max-message-size*))
  "Encode a query with known-answer suppression as one or more packets, per
RFC 6762 §7.2: the first carries the questions and as many known answers as fit,
every packet but the last sets the TC bit, and the follow-ups carry no questions
at all — only the remaining known answers.  Returns a list of octet vectors, in
the order they must be sent."
  (let* ((groups (or (chunk-records known-answers budget
                                    (lambda (group first)
                                      (query-message (if first questions '()) group)))
                     (list '())))
         (n (length groups)))
    (loop for group in groups
          for i from 1
          collect (encode-message
                   (query-message (if (= i 1) questions '())
                                  group
                                  (< i n))))))
