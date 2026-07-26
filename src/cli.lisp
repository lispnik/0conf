;;;; cli.lisp — a command-line front end for 0conf (system 0conf/cli).
;;;;
;;;; Sub-commands:
;;;;   0conf browse                 list the DNS-SD service types on the LAN
;;;;   0conf browse <type>          list instances of a type (e.g. _http._tcp)
;;;;   0conf resolve <instance>     resolve one instance to host / port / TXT
;;;;   0conf help                   usage
;;;;
;;;; Built as a standalone executable with `asdf:make :0conf/cli` (see
;;;; scripts/build-cli.sh).  Every command needs working multicast — on macOS a
;;;; raw binary needs the Local Network permission / multicast entitlement.

(defpackage #:0conf-cli
  (:use #:cl)
  (:export #:main #:toplevel))

(in-package #:0conf-cli)

(defparameter *program* "0conf"
  "Name printed in usage/help — matches the built executable.")

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

(defun print-service (info &optional (stream *standard-output*))
  "Print one SERVICE-INFO: name, host:port, addresses, and TXT key/values."
  (format stream "  ~A~%" (0conf:service-info-name info))
  (let ((host (0conf:service-info-host info)))
    (when (and host (plusp (length host)))
      (format stream "      at   ~A:~A~%" host (0conf:service-info-port info))))
  (dolist (a (0conf:service-info-addresses info))
    (format stream "      addr ~A~%" (addr-string a)))
  (loop for (k . v) in (0conf:service-info-txt info)
        for vs = (txt-value-string v)
        do (format stream "      txt  ~A~@[=~A~]~%" k vs)))

;;; --- sub-commands ----------------------------------------------------------

(defun browse-types (&key (timeout 3.0))
  (let ((types (0conf:enumerate-service-types :timeout timeout)))
    (cond
      (types
       (format t "~&Service types on the local network:~%~%")
       (dolist (ty types) (format t "  ~A~%" ty))
       (format t "~%~D type~:P.  See instances with: ~A browse <type>~%"
               (length types) *program*))
      (t
       (format t "~&No service types found.~%~
                  Nothing is advertising, or multicast isn't reaching the LAN ~
                  (on macOS a raw binary needs the Local Network permission /~%~
                  multicast entitlement — see doc/macos-multicast.md).~%")))
    0))

(defun browse-instances (type &key (timeout 3.0))
  (let ((infos (sort (copy-list (0conf:browse-once type :timeout timeout))
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
                (info (0conf:resolve fq)))
           (cond (info (format t "~&~A~%" fq) (print-service info) 0)
                 (t (format t "~&Not found: ~A~%" fq) 1)))))))

(defun usage (&optional (stream *standard-output*))
  (format stream "~&~A — browse and resolve mDNS / DNS-SD services on the local network.~2%~
                  Usage:~%~
                  ~2T~A browse              list the service types on the LAN~%~
                  ~2T~A browse <type>       list instances of a type (e.g. _http._tcp)~%~
                  ~2T~A resolve <instance>  resolve one instance to host / port / TXT~%~
                  ~2T~A help                show this help~%"
          *program* *program* *program* *program* *program*))

;;; --- entry point -----------------------------------------------------------

(defun main (&optional (argv (rest sb-ext:*posix-argv*)))
  "Dispatch a sub-command.  Returns a Unix exit code."
  (let ((cmd (first argv))
        (args (rest argv)))
    (cond
      ((null cmd) (usage) 1)
      ((string= cmd "browse") (cmd-browse args))
      ((string= cmd "resolve") (cmd-resolve args))
      ((member cmd '("help" "-h" "--help") :test #'string=) (usage) 0)
      (t (format *error-output* "~&~A: unknown command ~S~%~%" *program* cmd)
         (usage *error-output*)
         2))))

(defun toplevel ()
  "Executable entry point: run MAIN, print any error, and exit with its code."
  (sb-ext:exit
   :code (handler-case (or (main) 0)
           (error (e) (format *error-output* "~&~A: ~A~%" *program* e) 1))))
