;;;; octets.lisp — the wire codec's lowest layer: a byte-vector read/write
;;;; cursor plus DNS name (de)compression.  This is the pure, portable core;
;;;; nothing here touches the network.  Modeled on mafintosh/dns-packet.

(in-package #:0conf)

;;; ---------------------------------------------------------------------------
;;; String <-> octets.  DNS labels are byte strings; DNS-SD carries UTF-8.
;;; ---------------------------------------------------------------------------

(defun string->octets (string)
  (sb-ext:string-to-octets string :external-format :utf-8))

(defun normalize-name (name)
  "Return NAME in Unicode Normalization Form C (NFC), which RFC 6762 §16
recommends for mDNS names so that composed and decomposed spellings of the same
name produce identical bytes on the wire and compare equal.  ASCII is
unaffected.  Uses SBCL's built-in sb-unicode (no external dependency)."
  (sb-unicode:normalize-string name :nfc))

(defun octets->string (octets)
  (sb-ext:octets-to-string octets :external-format :utf-8))

(defun ensure-simple-octets (vector)
  "Return VECTOR as a (simple-array (unsigned-byte 8) (*)), copying if needed."
  (if (typep vector '(simple-array (unsigned-byte 8) (*)))
      vector
      (let ((out (make-array (length vector) :element-type '(unsigned-byte 8))))
        (replace out vector))))

;;; ---------------------------------------------------------------------------
;;; Writer
;;; ---------------------------------------------------------------------------

(defstruct (writer (:constructor make-writer))
  ;; Growable octet buffer.
  (bytes (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  ;; Name-suffix (string) -> byte offset, for compression pointers.
  (labels (make-hash-table :test 'equal)))

(declaim (inline writer-position))
(defun writer-position (writer)
  (fill-pointer (writer-bytes writer)))

(defun write-u8 (writer n)
  (vector-push-extend (logand n #xff) (writer-bytes writer)))

(defun write-u16 (writer n)
  (write-u8 writer (ldb (byte 8 8) n))
  (write-u8 writer (ldb (byte 8 0) n)))

(defun write-u32 (writer n)
  (write-u8 writer (ldb (byte 8 24) n))
  (write-u8 writer (ldb (byte 8 16) n))
  (write-u8 writer (ldb (byte 8 8) n))
  (write-u8 writer (ldb (byte 8 0) n)))

(defun write-octets (writer octets)
  (loop for b across octets do (write-u8 writer b)))

(defun writer-result (writer)
  "Snapshot the buffer as a fresh simple octet vector."
  (let* ((n (writer-position writer))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (replace out (writer-bytes writer))))

;;; Domain-name encoding with compression.
;;;
;;; NOTE: names are treated as dot-separated strings here.  That is correct for
;;; hostnames and service types (`_ipp._tcp.local`); DNS-SD *instance* labels can
;;; legally contain dots and need escaping — a later refinement (represent names
;;; as label lists internally).  Flagged as TODO.
(defun split-name (name)
  (remove "" (uiop:split-string name :separator '(#\.)) :test #'string=))

(defun write-name (writer name)
  ;; Normalize to NFC before encoding (RFC 6762 §16).  Compression suffixes are
  ;; therefore compared in normalized form too, so it stays consistent.
  (loop for tail on (split-name (normalize-name name))
        for suffix = (format nil "~{~A~^.~}" tail)
        for seen = (gethash suffix (writer-labels writer))
        do (cond
             (seen
              ;; Compression pointer: 0b11xxxxxx xxxxxxxx (top two bits set).
              (write-u16 writer (logior #xc000 seen))
              (return-from write-name))
             (t
              (let ((pos (writer-position writer)))
                (when (<= pos #x3fff)          ; only offsets that fit in 14 bits
                  (setf (gethash suffix (writer-labels writer)) pos)))
              (let ((label (string->octets (first tail))))
                (assert (<= (length label) 63) () "DNS label too long: ~S" (first tail))
                (write-u8 writer (length label))
                (write-octets writer label)))))
  ;; Root terminator (only reached when no pointer short-circuited us).
  (write-u8 writer 0))

;;; ---------------------------------------------------------------------------
;;; Reader
;;; ---------------------------------------------------------------------------

(defstruct (reader (:constructor make-reader (bytes)))
  (bytes #() :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(defun read-u8 (reader)
  (prog1 (aref (reader-bytes reader) (reader-pos reader))
    (incf (reader-pos reader))))

(defun read-u16 (reader)
  (logior (ash (read-u8 reader) 8) (read-u8 reader)))

(defun read-u32 (reader)
  (logior (ash (read-u8 reader) 24) (ash (read-u8 reader) 16)
          (ash (read-u8 reader) 8)  (read-u8 reader)))

(defun read-octets (reader n)
  (let* ((start (reader-pos reader))
         (end (+ start n)))
    (setf (reader-pos reader) end)
    (subseq (reader-bytes reader) start end)))

(defun read-name (reader)
  "Read a possibly-compressed domain name, following pointers.  Leaves the
reader positioned just past the name in the *current* stream (i.e. just past the
first pointer, if any was taken).

Hardened against hostile input: every compression pointer must jump strictly
backward, which forbids self-references and loops (targets strictly decrease, so
the chain must terminate) and bounds total work.  Signals an error on a
forward/self pointer or any read past the end of the message."
  (let ((bytes (reader-bytes reader))
        (end (length (reader-bytes reader)))
        (pos (reader-pos reader))
        (labels '())
        (jumped nil)
        (resume nil))
    (loop
      (when (>= pos end)
        (error "read-name: ran past end of message"))
      (let ((len (aref bytes pos)))
        (cond
          ((zerop len)
           (incf pos)
           (unless jumped (setf (reader-pos reader) pos))
           (return))
          ((= (logand len #xc0) #xc0)
           (when (>= (1+ pos) end)
             (error "read-name: truncated compression pointer"))
           (let ((ptr (logior (ash (logand len #x3f) 8) (aref bytes (1+ pos)))))
             ;; The loop guard: a pointer may only jump to an offset *before*
             ;; itself.  Well-formed DNS always does (a suffix must have appeared
             ;; earlier), and our own writer only records earlier offsets.
             (unless (< ptr pos)
               (error "read-name: non-backward compression pointer (~D -> ~D)" pos ptr))
             (unless jumped (setf resume (+ pos 2)))
             (setf jumped t
                   pos ptr)))
          (t
           (incf pos)
           (when (> (+ pos len) end)
             (error "read-name: label runs past end of message"))
           (push (octets->string (subseq bytes pos (+ pos len))) labels)
           (incf pos len)))))
    (when jumped (setf (reader-pos reader) resume))
    (format nil "~{~A~^.~}" (nreverse labels))))

;;; ---------------------------------------------------------------------------
;;; IPv4 helpers
;;; ---------------------------------------------------------------------------

(defun parse-ipv4 (string)
  "\"192.168.1.5\" -> #(192 168 1 5) as a simple octet vector."
  (let ((parts (split-name string)))
    (assert (= 4 (length parts)) () "Not a dotted-quad IPv4 address: ~S" string)
    (make-array 4 :element-type '(unsigned-byte 8)
                  :initial-contents (mapcar (lambda (p) (parse-integer p)) parts))))

(defun format-ipv4 (octets)
  (format nil "~D.~D.~D.~D" (aref octets 0) (aref octets 1)
          (aref octets 2) (aref octets 3)))

;;; ---------------------------------------------------------------------------
;;; IPv6 helpers
;;; ---------------------------------------------------------------------------

(defun parse-ipv6 (string)
  "Parse an IPv6 address (with optional \"::\" zero-compression) into a 16-octet
simple vector.  E.g. \"ff02::fb\" -> #(#xff #x02 0 ... 0 #xfb).
TODO: embedded-IPv4 forms like \"::ffff:1.2.3.4\" are not handled."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (dbl (search "::" string)))
    (flet ((groups (s)
             (if (zerop (length s))
                 '()
                 (mapcar (lambda (g) (parse-integer g :radix 16))
                         (uiop:split-string s :separator '(#\:))))))
      (cond
        (dbl
         (let ((head (groups (subseq string 0 dbl)))
               (tail (groups (subseq string (+ dbl 2)))))
           (assert (<= (+ (length head) (length tail)) 8) ()
                   "Too many groups in IPv6 address: ~S" string)
           (loop for g in head for i from 0 by 2
                 do (setf (aref out i) (ldb (byte 8 8) g)
                          (aref out (1+ i)) (ldb (byte 8 0) g)))
           (loop for g in (reverse tail) for i downfrom 14 by 2
                 do (setf (aref out i) (ldb (byte 8 8) g)
                          (aref out (1+ i)) (ldb (byte 8 0) g)))))
        (t
         (let ((gs (groups string)))
           (assert (= 8 (length gs)) () "Malformed IPv6 (need 8 groups): ~S" string)
           (loop for g in gs for i from 0 by 2
                 do (setf (aref out i) (ldb (byte 8 8) g)
                          (aref out (1+ i)) (ldb (byte 8 0) g)))))))
    out))

(defun format-ipv6 (octets)
  "A colon-hex rendering of a 16-octet vector.  Not the RFC 5952 canonical
form (no \"::\" compression), but fine for display/logging."
  (string-downcase
   (format nil "~{~x~^:~}"
           (loop for i from 0 below 16 by 2
                 collect (logior (ash (aref octets i) 8) (aref octets (1+ i)))))))
