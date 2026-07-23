;;;; records.lisp — CLOS resource records and their rdata codecs.
;;;;
;;;; Base class holds the common header (name/type/class/ttl + the mDNS
;;;; cache-flush flag).  Each concrete type specialises WRITE-RDATA; decoding is
;;;; dispatched by numeric type in DECODE-RECORD.  Adding a type means: one
;;;; subclass + one WRITE-RDATA method + one DECODE-RECORD clause.

(in-package #:0conf)

(defclass resource-record ()
  ((name        :initarg :name        :accessor rr-name        :type string)
   (rtype       :initarg :rtype       :accessor rr-type)
   (rclass      :initarg :rclass      :accessor rr-class       :initform +class-in+)
   (cache-flush :initarg :cache-flush :accessor rr-cache-flush :initform nil)
   (ttl         :initarg :ttl         :accessor rr-ttl         :initform 120)))

(defgeneric write-rdata (record writer)
  (:documentation "Write RECORD's type-specific rdata (no header) to WRITER."))

(defmethod print-object ((r resource-record) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~A ttl=~D~:[~; flush~]"
            (rr-name r) (rr-ttl r) (rr-cache-flush r))))

;;; --- A (IPv4 address) ------------------------------------------------------

(defclass a-record (resource-record)
  ((address :initarg :address :accessor a-address
            :documentation "IPv4 address as a 4-octet simple vector."))
  (:default-initargs :rtype +type-a+))

(defmethod write-rdata ((r a-record) w)
  (write-octets w (a-address r)))

;;; --- AAAA (IPv6 address) ---------------------------------------------------

(defclass aaaa-record (resource-record)
  ((address :initarg :address :accessor aaaa-address
            :documentation "IPv6 address as a 16-octet simple vector."))
  (:default-initargs :rtype +type-aaaa+))

(defmethod write-rdata ((r aaaa-record) w)
  (write-octets w (aaaa-address r)))

;;; --- PTR (name pointer; DNS-SD enumerates instances with these) ------------

(defclass ptr-record (resource-record)
  ((target :initarg :target :accessor ptr-target :type string))
  (:default-initargs :rtype +type-ptr+))

(defmethod write-rdata ((r ptr-record) w)
  (write-name w (ptr-target r)))

;;; --- SRV (host + port for a service instance; RFC 2782) --------------------

(defclass srv-record (resource-record)
  ((priority :initarg :priority :accessor srv-priority :initform 0)
   (weight   :initarg :weight   :accessor srv-weight   :initform 0)
   (port     :initarg :port     :accessor srv-port)
   (target   :initarg :target   :accessor srv-target   :type string))
  (:default-initargs :rtype +type-srv+))

(defmethod write-rdata ((r srv-record) w)
  (write-u16 w (srv-priority r))
  (write-u16 w (srv-weight r))
  (write-u16 w (srv-port r))
  (write-name w (srv-target r)))

;;; --- TXT (list of length-prefixed character-strings) -----------------------

(defclass txt-record (resource-record)
  ((strings :initarg :strings :accessor txt-strings :initform '()
            :documentation "List of strings, each an mDNS \"character-string\" (<=255 bytes)."))
  (:default-initargs :rtype +type-txt+))

(defmethod write-rdata ((r txt-record) w)
  ;; DNS-SD: an empty TXT record must still carry a single empty string.
  (let ((strings (or (txt-strings r) '(""))))
    (dolist (s strings)
      (let ((octets (string->octets s)))
        (assert (<= (length octets) 255) () "TXT character-string too long: ~S" s)
        (write-u8 w (length octets))
        (write-octets w octets)))))

;;; --- NSEC (which record types exist at a name; mDNS negative responses) ----

(defclass nsec-record (resource-record)
  ((next-name :initarg :next-name :accessor nsec-next-name :type string)
   (types     :initarg :types     :accessor nsec-types     :initform '()
              :documentation "List of record-type numbers present at this name."))
  (:default-initargs :rtype +type-nsec+))

(defun write-type-bitmap (w types)
  "Encode TYPES (a list of rrtype numbers) as RFC 4034 §4.1.2 window blocks."
  ;; Group types by their high byte (the \"window\").
  (let ((windows (make-hash-table)))
    (dolist (type types)
      (push (logand type #xff) (gethash (ash type -8) windows)))
    (dolist (window (sort (alexandria:hash-table-keys windows) #'<))
      (let* ((lows (gethash window windows))
             (nbytes (1+ (ash (reduce #'max lows) -3)))
             (bitmap (make-array nbytes :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
        (dolist (low lows)
          (setf (aref bitmap (ash low -3))
                (logior (aref bitmap (ash low -3))
                        (ash #x80 (- (logand low 7))))))
        (write-u8 w window)
        (write-u8 w nbytes)
        (write-octets w bitmap)))))

(defun read-type-bitmap (r end)
  "Decode window blocks until the reader reaches byte offset END."
  (let ((types '()))
    (loop while (< (reader-pos r) end)
          do (let ((window (read-u8 r))
                   (nbytes (read-u8 r)))
               (dotimes (i nbytes)
                 (let ((byte (read-u8 r)))
                   (dotimes (bit 8)
                     (when (logbitp (- 7 bit) byte)
                       (push (+ (ash window 8) (ash i 3) bit) types)))))))
    (nreverse types)))

(defmethod write-rdata ((r nsec-record) w)
  (write-name w (nsec-next-name r))
  (write-type-bitmap w (nsec-types r)))

;;; --- fallback for types we don't model yet ---------------------------------

(defclass unknown-record (resource-record)
  ((rdata :initarg :rdata :accessor rr-rdata
          :documentation "Raw, undecoded rdata octets.")))

(defmethod write-rdata ((r unknown-record) w)
  (write-octets w (rr-rdata r)))

;;; ---------------------------------------------------------------------------
;;; Header framing shared by every record.
;;; ---------------------------------------------------------------------------

(defun write-record (writer record)
  (write-name writer (rr-name record))
  (write-u16 writer (rr-type record))
  (write-u16 writer (logior (rr-class record)
                            (if (rr-cache-flush record) +cache-flush-bit+ 0)))
  (write-u32 writer (rr-ttl record))
  ;; rdlength is unknown until the rdata is written, so reserve two bytes and
  ;; backpatch.  Compression offsets inside rdata are absolute, so this is safe.
  (let ((len-pos (writer-position writer)))
    (write-u16 writer 0)
    (let ((start (writer-position writer)))
      (write-rdata record writer)
      (let ((rdlength (- (writer-position writer) start)))
        (setf (aref (writer-bytes writer) len-pos)      (ldb (byte 8 8) rdlength)
              (aref (writer-bytes writer) (1+ len-pos)) (ldb (byte 8 0) rdlength))))))

(defun read-record (reader)
  (let* ((name        (read-name reader))
         (rtype       (read-u16 reader))
         (raw-class   (read-u16 reader))
         (ttl         (read-u32 reader))
         (rdlength    (read-u16 reader))
         (rclass      (logand raw-class (lognot +cache-flush-bit+)))
         (cache-flush (logtest raw-class +cache-flush-bit+)))
    (decode-record rtype reader
                   :name name :rclass rclass :cache-flush cache-flush
                   :ttl ttl :rdlength rdlength)))

(defun decode-record (rtype reader &key name rclass cache-flush ttl rdlength)
  (let ((common (list :name name :rclass rclass :cache-flush cache-flush :ttl ttl))
        (end (+ (reader-pos reader) rdlength)))    ; rdata ends here
    (macrolet ((rec (class &rest slots)
                 `(apply #'make-instance ',class (list* ,@slots common))))
      (case rtype
        (#.+type-a+    (rec a-record    :address (read-octets reader 4)))
        (#.+type-aaaa+ (rec aaaa-record :address (read-octets reader 16)))
        (#.+type-ptr+  (rec ptr-record  :target (read-name reader)))
        (#.+type-srv+  (rec srv-record
                            :priority (read-u16 reader)
                            :weight   (read-u16 reader)
                            :port     (read-u16 reader)
                            :target   (read-name reader)))
        (#.+type-txt+  (rec txt-record  :strings (read-txt-strings reader end)))
        (#.+type-nsec+ (rec nsec-record
                            :next-name (read-name reader)
                            :types     (read-type-bitmap reader end)))
        (t (rec unknown-record :rtype rtype :rdata (read-octets reader rdlength)))))))

(defun read-txt-strings (reader end)
  (loop while (< (reader-pos reader) end)
        for len = (read-u8 reader)
        collect (octets->string (read-octets reader len))))
