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
