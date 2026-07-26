;;;; cli.lisp — a command-line front end for 0conf (system 0conf/cli).
;;;;
;;;; Sub-commands:
;;;;   0conf browse                 list the DNS-SD service types on the LAN
;;;;   0conf browse <type>          list instances of a type (e.g. _http._tcp)
;;;;   0conf monitor                live, self-updating view of all services
;;;;   0conf resolve <instance>     resolve one instance to host / port / TXT
;;;;   0conf help                   usage
;;;;
;;;; A leading `-i <addr>` / `--interface <addr>` pins the multicast egress
;;;; interface for the one-shot commands (browse/resolve).
;;;;
;;;; Built as a standalone executable with `asdf:make :0conf/cli` (see
;;;; scripts/build-cli.sh).  Every command needs working multicast — on macOS a
;;;; raw binary needs Local Network access (see doc/macos-multicast.md).

(defpackage #:0conf-cli
  (:use #:cl)
  (:export #:main #:toplevel))

(in-package #:0conf-cli)

(defparameter *program* "0conf"
  "Name printed in usage/help — matches the built executable.")

(defvar *interface* nil
  "Dotted-quad egress interface for the one-shot commands, or NIL for the default.")

(defparameter +esc+ (code-char 27))

(defparameter +well-known-types+
  '("_http._tcp.local" "_https._tcp.local"
    "_ipp._tcp.local" "_ipps._tcp.local" "_printer._tcp.local" "_pdl-datastream._tcp.local"
    "_scanner._tcp.local" "_uscan._tcp.local" "_uscans._tcp.local"
    "_airplay._tcp.local" "_raop._tcp.local" "_airport._tcp.local" "_appletv-v2._tcp.local"
    "_companion-link._tcp.local" "_touch-able._tcp.local" "_device-info._tcp.local"
    "_googlecast._tcp.local" "_spotify-connect._tcp.local" "_sonos._tcp.local"
    "_soundtouch._tcp.local" "_amzn-wplay._tcp.local"
    "_hap._tcp.local" "_matter._tcp.local" "_meshcop._udp.local"
    "_ssh._tcp.local" "_sftp-ssh._tcp.local" "_rfb._tcp.local" "_teamviewer._tcp.local"
    "_smb._tcp.local" "_afpovertcp._tcp.local" "_nfs._tcp.local" "_webdav._tcp.local"
    "_daap._tcp.local" "_dacp._tcp.local" "_workstation._tcp.local")
  "Common DNS-SD types the live monitor always browses, on top of whatever the
meta-query enumerates — some devices answer a direct browse but not the type
enumeration.  A type with no instances stays silent, so this only ever adds.")

;;; --- formatting helpers ----------------------------------------------------

(defun ensure-local (name)
  "Append `.local` to a bare service type / instance if the user left it off."
  (let ((n (string-right-trim "." name)))
    (if (search ".local" n :from-end t)
        n
        (concatenate 'string n ".local"))))

(defun addr-string (a)
  "Render an address record's octets as text (IPv4 or IPv6)."
  (case (length a)
    (4  (0conf:format-ipv4 a))
    (16 (0conf:format-ipv6 a))
    (t  (princ-to-string a))))

(defun txt-value-string (v)
  "A TXT value is NIL (bare key), a string, or raw octets."
  (cond ((null v) nil)
        ((stringp v) v)
        (t (map 'string #'code-char v))))

(defun host-port (info)
  "\"host:port\" for INFO, or \"\" if its host isn't known yet."
  (let ((h (0conf:service-info-host info)))
    (if (and h (plusp (length h)))
        (format nil "~A:~A" h (0conf:service-info-port info))
        "")))

(defun print-service (info &optional (stream *standard-output*))
  "Print one SERVICE-INFO: name, host:port, addresses, and TXT key/values."
  (format stream "  ~A~%" (0conf:service-info-name info))
  (let ((hp (host-port info)))
    (when (plusp (length hp)) (format stream "      at   ~A~%" hp)))
  (dolist (a (0conf:service-info-addresses info))
    (format stream "      addr ~A~%" (addr-string a)))
  (loop for (k . v) in (0conf:service-info-txt info)
        for vs = (txt-value-string v)
        do (format stream "      txt  ~A~@[=~A~]~%" k vs)))

;;; --- browse / resolve (one-shot) -------------------------------------------

(defun browse-types (&key (timeout 3.0))
  (let ((types (0conf:enumerate-service-types :timeout timeout :interface *interface*)))
    (cond
      (types
       (format t "~&Service types on the local network:~%~%")
       (dolist (ty types) (format t "  ~A~%" ty))
       (format t "~%~D type~:P.  See instances with: ~A browse <type>~%"
               (length types) *program*))
      (t
       (format t "~&No service types found.~%~
                  Nothing is advertising, or multicast isn't reaching the LAN ~
                  (on macOS a raw binary needs Local Network access —~%~
                  see doc/macos-multicast.md).~%")))
    0))

(defun browse-instances (type &key (timeout 3.0))
  (let ((infos (sort (copy-list (0conf:browse-once type :timeout timeout :interface *interface*))
                     #'string-lessp :key #'0conf:service-info-name)))
    (cond
      (infos
       (format t "~&~D instance~:P of ~A:~%~%" (length infos) type)
       (dolist (i infos) (print-service i) (terpri)))
      (t (format t "~&No instances of ~A found.~%" type)))
    0))

(defun cmd-browse (args)
  (let ((type (first args)))
    (if (and type (plusp (length type)))
        (browse-instances (ensure-local type))
        (browse-types))))

(defun cmd-resolve (args)
  (let ((instance (first args)))
    (cond
      ((null instance)
       (format *error-output* "usage: ~A resolve <instance._type._tcp.local>~%" *program*)
       2)
      (t (let* ((fq (ensure-local instance))
                (info (0conf:resolve fq :interface *interface*)))
           (cond (info (format t "~&~A~%" fq) (print-service info) 0)
                 (t (format t "~&Not found: ~A~%" fq) 1)))))))

;;; --- monitor (live view) ---------------------------------------------------
;;;
;;; Starts a responder (one socket per interface, so it watches every link),
;;; enumerates the service types, and keeps a live browser per type.  A shared
;;; table of instances is redrawn as services appear, change, and disappear.

(defun render-monitor (infos)
  (let ((by-type (make-hash-table :test 'equal)))
    (dolist (i infos)
      (push i (gethash (0conf:service-info-type i) by-type)))
    (format t "~C[H~C[2J" +esc+ +esc+)                 ; home + clear
    (format t "~A monitor — ~D service~:P across ~D type~:P   (Ctrl-C to quit)~2%"
            *program* (length infos) (hash-table-count by-type))
    (if (null infos)
        (format t "  discovering services on the local network…~%")
        (dolist (ty (sort (loop for k being the hash-keys of by-type collect k) #'string<))
          (format t "~C[1m~A~C[0m~%" +esc+ ty +esc+)   ; bold type header
          (dolist (i (sort (copy-list (gethash ty by-type))
                           #'string-lessp :key #'0conf:service-info-name))
            (format t "    ~30A ~A~%" (0conf:service-info-name i) (host-port i)))
          (terpri)))
    (finish-output)))

(defun cmd-monitor (args)
  (declare (ignore args))
  (let ((responder (0conf:start-responder (0conf:make-responder)))
        (services (make-hash-table :test 'equal))     ; instance name -> service-info
        (browsers (make-hash-table :test 'equal))     ; type -> service-browser
        (lock (bordeaux-threads:make-lock "monitor"))
        (running t)
        (type-thread nil))
    (labels ((put (i) (bordeaux-threads:with-lock-held (lock)
                        (setf (gethash (0conf:service-instance-name i) services) i)))
             (del (n) (bordeaux-threads:with-lock-held (lock)
                        (remhash n services)))
             (ensure-browser (ty)
               (bordeaux-threads:with-lock-held (lock)
                 (unless (gethash ty browsers)
                   (setf (gethash ty browsers)
                         (0conf:browse-services responder ty
                                                :on-add    #'put
                                                :on-update #'put
                                                :on-remove #'del)))))
             (snapshot ()
               (bordeaux-threads:with-lock-held (lock)
                 (loop for i being the hash-values of services collect i))))
      (unwind-protect
           (progn
             (format t "~C[?25l" +esc+)                ; hide cursor
             (format t "~C[H~C[2J  discovering services…~%" +esc+ +esc+)
             (finish-output)
             ;; always sweep the well-known types (some devices answer a direct
             ;; browse but ignore the meta-query)
             (dolist (ty +well-known-types+) (ensure-browser ty))
             ;; ...and keep discovering any *other* types the network advertises
             (setf type-thread
                   (bordeaux-threads:make-thread
                    (lambda ()
                      (loop while running do
                        (dolist (ty (ignore-errors
                                     (0conf:enumerate-service-types :timeout 2.0)))
                          (ensure-browser ty))
                        (sleep 4)))
                    :name "0conf-type-poll"))
             ;; redraw on the main thread until Ctrl-C
             (handler-case
                 (loop while running do
                   (render-monitor (snapshot))
                   (sleep 1.0))
               (sb-sys:interactive-interrupt () nil)))
        (setf running nil)
        (when type-thread (ignore-errors (bordeaux-threads:join-thread type-thread)))
        (bordeaux-threads:with-lock-held (lock)
          (maphash (lambda (ty b) (declare (ignore ty)) (ignore-errors (0conf:stop-browse b)))
                   browsers))
        (ignore-errors (0conf:stop-responder responder))
        (format t "~C[?25h~%" +esc+))))                ; show cursor
  0)

;;; --- dispatch --------------------------------------------------------------

(defun extract-interface (argv)
  "Pull a `-i <addr>` / `--interface <addr>` / `--interface=<addr>` option out of
ARGV.  Returns (values interface remaining-args)."
  (let ((iface nil) (out '()) (rest argv))
    (loop while rest
          for a = (pop rest)
          do (cond
               ((and (member a '("-i" "--interface") :test #'string=) rest)
                (setf iface (pop rest)))
               ((and (> (length a) 12) (string= "--interface=" (subseq a 0 12)))
                (setf iface (subseq a 12)))
               (t (push a out))))
    (values iface (nreverse out))))

(defun usage (&optional (stream *standard-output*))
  (format stream "~&~A — browse and resolve mDNS / DNS-SD services on the local network.~2%~
                  Usage:~%~
                  ~2T~A browse              list the service types on the LAN~%~
                  ~2T~A browse <type>       list instances of a type (e.g. _http._tcp)~%~
                  ~2T~A monitor             live, self-updating view of all services~%~
                  ~2T~A resolve <instance>  resolve one instance to host / port / TXT~%~
                  ~2T~A help                show this help~2%~
                  Options:~%~
                  ~2T-i, --interface <addr>  pin the multicast egress interface ~
                  (browse/resolve)~%"
          *program* *program* *program* *program* *program* *program*))

(defun main (&optional (argv (rest sb-ext:*posix-argv*)))
  "Dispatch a sub-command.  Returns a Unix exit code."
  (multiple-value-bind (iface rest) (extract-interface argv)
    (let ((*interface* iface)
          (cmd (first rest))
          (args (rest rest)))
      (cond
        ((null cmd) (usage) 1)
        ((string= cmd "browse") (cmd-browse args))
        ((string= cmd "monitor") (cmd-monitor args))
        ((string= cmd "resolve") (cmd-resolve args))
        ((member cmd '("help" "-h" "--help") :test #'string=) (usage) 0)
        (t (format *error-output* "~&~A: unknown command ~S~%~%" *program* cmd)
           (usage *error-output*)
           2)))))

(defun toplevel ()
  "Executable entry point: run MAIN, print any error, and exit with its code."
  (sb-ext:exit
   :code (handler-case (or (main) 0)
           (error (e) (format *error-output* "~&~A: ~A~%" *program* e) 1))))
