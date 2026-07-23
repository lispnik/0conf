;;;; cache.lisp — record cache with TTL expiry and cache-flush semantics.
;;;;
;;;; Records are bucketed by (name, type, class).  Each stored entry remembers
;;;; the absolute universal-time at which it expires (added-at + ttl).  This is
;;;; the analog of python-zeroconf's _cache.py; the responder and browser read
;;;; and write it.

(in-package #:0conf)

(defstruct (cache-entry (:constructor make-cache-entry (record expires)))
  record
  (expires 0 :type integer))            ; universal time (seconds) of expiry

(defstruct (cache (:constructor make-cache))
  ;; bucket-key string -> list of cache-entry
  (table (make-hash-table :test 'equal)))

(defun bucket-key (name type class)
  (format nil "~A|~D|~D" (string-downcase name) type class))

(defun record-bucket-key (record)
  (bucket-key (rr-name record) (rr-type record) (rr-class record)))

(defun rdata-octets (record)
  "The record's rdata as an octet vector — used to test two records for
rdata-identity within a bucket."
  (let ((w (make-writer)))
    (write-rdata record w)
    (writer-result w)))

(defun rdata-equal (a b)
  (equalp (rdata-octets a) (rdata-octets b)))

(defun cache-add (cache record &optional (now (get-universal-time)))
  "Insert RECORD.  A ttl of 0 is an mDNS \"goodbye\" (remove the matching
record).  The cache-flush bit removes other records of the same name/type/class.
Returns :ADDED, :UPDATED, or :REMOVED."
  (let* ((key (record-bucket-key record))
         (bucket (gethash key (cache-table cache))))
    (cond
      ;; Goodbye: drop the entry whose rdata matches.
      ((zerop (rr-ttl record))
       (setf (gethash key (cache-table cache))
             (remove-if (lambda (e) (rdata-equal (cache-entry-record e) record)) bucket))
       :removed)
      (t
       ;; cache-flush: this record supersedes differing records in the bucket.
       ;; (RFC 6762 §10.2 defers the flush by 1s to absorb multi-packet
       ;; responses; we flush immediately here — TODO for the nuance.)
       (when (rr-cache-flush record)
         (setf bucket
               (remove-if-not (lambda (e) (rdata-equal (cache-entry-record e) record))
                              bucket)))
       (let ((existing (find-if (lambda (e) (rdata-equal (cache-entry-record e) record))
                                bucket))
             (expires (+ now (rr-ttl record))))
         (cond
           (existing                    ; refresh ttl / replace record in place
            (setf (cache-entry-record existing) record
                  (cache-entry-expires existing) expires
                  (gethash key (cache-table cache)) bucket)
            :updated)
           (t
            (setf (gethash key (cache-table cache))
                  (cons (make-cache-entry record expires) bucket))
            :added)))))))

(defun cache-get (cache name &optional type (class +class-in+)
                             (now (get-universal-time)))
  "Live (unexpired) records for NAME, optionally filtered to TYPE."
  (if type
      (mapcar #'cache-entry-record
              (remove-if (lambda (e) (< (cache-entry-expires e) now))
                         (gethash (bucket-key name type class) (cache-table cache))))
      ;; any type: scan buckets for this name
      (let ((prefix (format nil "~A|" (string-downcase name)))
            (out '()))
        (maphash (lambda (key entries)
                   (when (eql 0 (search prefix key))
                     (dolist (e entries)
                       (when (>= (cache-entry-expires e) now)
                         (push (cache-entry-record e) out)))))
                 (cache-table cache))
        (nreverse out))))

(defun cache-all (cache &optional (now (get-universal-time)))
  "Every live record in the cache."
  (let ((out '()))
    (maphash (lambda (key entries)
               (declare (ignore key))
               (dolist (e entries)
                 (when (>= (cache-entry-expires e) now)
                   (push (cache-entry-record e) out))))
             (cache-table cache))
    (nreverse out)))

(defun cache-expire (cache &optional (now (get-universal-time)))
  "Drop expired entries.  Returns the number removed."
  (let ((removed 0))
    (maphash (lambda (key entries)
               (let ((live (remove-if (lambda (e) (< (cache-entry-expires e) now))
                                      entries)))
                 (incf removed (- (length entries) (length live)))
                 (if live
                     (setf (gethash key (cache-table cache)) live)
                     (remhash key (cache-table cache)))))
             (cache-table cache))
    removed))
