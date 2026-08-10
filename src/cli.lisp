;;;; cli.lisp — a command-line front end for 0conf (system 0conf/cli).
;;;;
;;;; Sub-commands:
;;;;   0conf browse [<type>]          list service types, or instances of a type
;;;;   0conf monitor                  live, self-updating view of all services
;;;;   0conf resolve <instance>       resolve one instance to host / port / TXT
;;;;   0conf publish <type> <name> <port>   advertise a service until Ctrl-C
;;;;   0conf interfaces               list usable network interfaces
;;;;   0conf help | --version
;;;;
;;;; Global options: -i/--interface <name|addr|index>, --timeout <secs>, --json,
;;;;   --color auto|always|never, -6/--ipv6, -4/--ipv4.
;;;;
;;;; Built as a standalone executable with `asdf:make :0conf/cli` (see
;;;; scripts/build-cli.sh).  Every command needs working multicast — on macOS a
;;;; raw binary needs Local Network access (see doc/macos-multicast.md).

(defpackage #:0conf-cli
  (:use #:cl)
  (:export #:main #:toplevel))

(in-package #:0conf-cli)

(defparameter *program* "0conf")

(defparameter +version+
  (or (ignore-errors (asdf:component-version (asdf:find-system "0conf")))
      "unknown")
  "Resolved from the ASDF system at image-save time, so the binary needs no ASDF.")

(defparameter +esc+ (code-char 27))

;;; per-invocation options (bound in MAIN)
(defvar *interface* nil)                ; egress interface as typed (name / v4 dotted-quad / v6 index)
(defvar *timeout* 3.0)                  ; seconds for one-shot queries
(defvar *family* :ipv4)                 ; :ipv4 or :ipv6
(defvar *json* nil)                     ; machine-readable output
(defvar *ansi* nil)                     ; may use cursor movement / redraw (a TTY)
(defvar *color* nil)                    ; may emit color / bold

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
meta-query enumerates — some devices answer a direct browse but not the
enumeration.  A type with no instances stays silent, so this only ever adds.")

;;; --- errors ----------------------------------------------------------------

(define-condition cli-error (error)
  ((message :initarg :message :reader cli-error-message))
  (:report (lambda (c s) (write-string (cli-error-message c) s))))

(defun cli-error (fmt &rest args)
  (error 'cli-error :message (apply #'format nil fmt args)))

;;; --- text helpers ----------------------------------------------------------

(defun ensure-local (name)
  "Append `.local` to a bare service type / instance if the user left it off."
  (let ((n (string-right-trim "." name)))
    (if (search ".local" n :from-end t)
        n
        (concatenate 'string n ".local"))))

(defun addr-string (a)
  (case (length a)
    (4  (0conf:format-ipv4 a))
    (16 (0conf:format-ipv6 a))
    (t  (princ-to-string a))))

(defun sanitize (string)
  "Render STRING with control / non-printable bytes escaped as \\xNN, so a raw ESC
in a service name or TXT value can't corrupt or inject into the terminal."
  (with-output-to-string (o)
    (loop for ch across string
          for code = (char-code ch)
          do (if (or (< code 32) (= code 127))
                 (format o "\\x~2,'0X" code)
                 (write-char ch o)))))

(defun txt-value-string (v)
  "A TXT value is NIL (bare key), a string, or raw octets.  Returns a display
string (sanitized) or NIL for a keyless entry."
  (cond ((null v) nil)
        ((stringp v) (sanitize v))
        (t (sanitize (map 'string #'code-char v)))))

(defun host-port (info)
  (let ((h (0conf:service-info-host info)))
    (if (and h (plusp (length h)))
        (format nil "~A:~A" (sanitize h) (0conf:service-info-port info))
        "")))

(defun fit (s width)
  "Truncate S to WIDTH characters with an ellipsis (keeps table columns aligned)."
  (if (> (length s) width)
      (concatenate 'string (subseq s 0 (1- width)) "…")
      s))

(defun hash-keys (h) (loop for k being the hash-keys of h collect k))

;;; --- terminal (no-ops unless *ansi* / *color*) -----------------------------

(defun bold (s) (if *color* (format nil "~C[1m~A~C[0m" +esc+ s +esc+) s))
(defun clear-home () (when *ansi* (format t "~C[H~C[2J" +esc+ +esc+)))
(defun hide-cursor () (when *ansi* (format t "~C[?25l" +esc+)))
(defun show-cursor () (when *ansi* (format t "~C[?25h" +esc+)))

;;; --- JSON emitter (small hand-rolled — no dependency) ----------------------

(defun jstr (s)
  "S as a JSON string literal."
  (with-output-to-string (o)
    (write-char #\" o)
    (loop for ch across s for c = (char-code ch)
          do (case ch
               (#\" (write-string "\\\"" o))
               (#\\ (write-string "\\\\" o))
               (#\Newline (write-string "\\n" o))
               (#\Return (write-string "\\r" o))
               (#\Tab (write-string "\\t" o))
               (t (if (< c 32) (format o "\\u~4,'0X" c) (write-char ch o)))))
    (write-char #\" o)))

(defun txt-json (alist)
  (format nil "{~{~A~^,~}}"
          (loop for (k . v) in alist
                for vs = (let ((s (txt-value-string v))) (if s (jstr s) "null"))
                collect (format nil "~A:~A" (jstr k) vs))))

(defun service-json (info)
  (format nil "{~A:~A,~A:~A,~A:~A,~A:~D,~A:[~{~A~^,~}],~A:~A}"
          (jstr "name") (jstr (0conf:service-info-name info))
          (jstr "type") (jstr (0conf:service-info-type info))
          (jstr "host") (jstr (or (0conf:service-info-host info) ""))
          (jstr "port") (0conf:service-info-port info)
          (jstr "addresses") (mapcar (lambda (a) (jstr (addr-string a)))
                                     (0conf:service-info-addresses info))
          (jstr "txt") (txt-json (0conf:service-info-txt info))))

(defun services-json (infos)
  (format nil "[~{~A~^,~}]" (mapcar #'service-json infos)))

;;; --- human printing --------------------------------------------------------

(defun print-service (info &optional (stream *standard-output*))
  (format stream "  ~A~%" (sanitize (0conf:service-info-name info)))
  (let ((hp (host-port info)))
    (when (plusp (length hp)) (format stream "      at   ~A~%" hp)))
  (dolist (a (0conf:service-info-addresses info))
    (format stream "      addr ~A~%" (addr-string a)))
  (loop for (k . v) in (0conf:service-info-txt info)
        for vs = (txt-value-string v)
        do (format stream "      txt  ~A~@[=~A~]~%" (sanitize k) vs)))

;;; --- interface arg conversion ----------------------------------------------
;;;
;;; -i accepts a NIC name ("en0", "utun3") in either family, plus the raw form
;;; the socket layer wants: a dotted-quad for IPv4, an interface index for IPv6.
;;; Names are resolved against getifaddrs(3), so an unknown one fails here with
;;; the list of candidates rather than deep inside a setsockopt.

(defun known-interfaces ()
  "Every interface the OS reports, not just the multicast-capable ones — pinning
to something odd is the user's call, and a narrower list makes a valid name look
unknown."
  (0conf:list-interfaces :include-loopback t :multicast-only nil))

(defun interface-hint (ifs)
  (format nil "known interfaces: ~{~A~^, ~} (see `~A interfaces`)"
          (mapcar #'0conf:net-interface-name ifs) *program*))

(defun find-interface (name ifs)
  (or (find name ifs :key #'0conf:net-interface-name :test #'string=)
      (cli-error "unknown interface ~A — ~A" name (interface-hint ifs))))

(defun iface-arg ()
  "*INTERFACE* in the form MAKE-MDNS-SOCKET wants for the current family: an
IPv4 dotted-quad string, or an IPv6 interface index."
  (cond
    ((null *interface*) nil)
    ((eq *family* :ipv6)
     (or (ignore-errors (parse-integer *interface*))
         (let* ((ifs (known-interfaces))
                (nif (find-interface *interface* ifs)))
           (or (0conf:net-interface-index nif)
               (cli-error "interface ~A has no index — ~A" *interface* (interface-hint ifs))))))
    ((ignore-errors (0conf:parse-ipv4 *interface*)) *interface*)
    ;; digits and dots and still not parseable: meant as an address, not a name
    ((every (lambda (c) (or (digit-char-p c) (char= c #\.))) *interface*)
     (cli-error "not a valid IPv4 address: ~A" *interface*))
    (t (let* ((ifs (known-interfaces))
              (nif (find-interface *interface* ifs)))
         (or (and (0conf:net-interface-ipv4 nif)
                  (0conf:format-ipv4 (0conf:net-interface-ipv4 nif)))
             (cli-error "interface ~A has no IPv4 address (try -6, or pass a dotted-quad)"
                        *interface*))))))

;;; --- browse / resolve (one-shot) -------------------------------------------

(defun browse-types ()
  (let ((types (0conf:enumerate-service-types :timeout *timeout*
                                              :interface (iface-arg) :family *family*)))
    (cond
      (*json* (format t "[~{~A~^,~}]~%" (mapcar #'jstr types)) (if types 0 1))
      (types
       (format t "~&Service types on the local network:~%~%")
       (dolist (ty types) (format t "  ~A~%" ty))
       (format t "~%~D type~:P.  See instances with: ~A browse <type>~%"
               (length types) *program*)
       0)
      (t
       (format t "~&No service types found.~%~
                  Nothing is advertising, or multicast isn't reaching the LAN ~
                  (on macOS a raw binary needs Local Network access —~%~
                  see doc/macos-multicast.md).~%")
       1))))

(defun browse-instances (type)
  (let ((infos (sort (copy-list (0conf:browse-once type :timeout *timeout*
                                                   :interface (iface-arg) :family *family*))
                     #'string-lessp :key #'0conf:service-info-name)))
    (cond
      (*json* (format t "~A~%" (services-json infos)) (if infos 0 1))
      (infos
       (format t "~&~D instance~:P of ~A:~%~%" (length infos) type)
       (dolist (i infos) (print-service i) (terpri))
       0)
      (t (format t "~&No instances of ~A found.~%" type) 1))))

(defun cmd-browse (pos)
  (let ((type (first pos)))
    (if (and type (plusp (length type)))
        (browse-instances (ensure-local type))
        (browse-types))))

(defun cmd-resolve (pos)
  (let ((instance (first pos)))
    (when (null instance)
      (cli-error "usage: ~A resolve <instance._type._tcp.local>" *program*))
    (let* ((fq (ensure-local instance))
           (info (0conf:resolve fq :timeout *timeout* :interface (iface-arg) :family *family*)))
      (cond
        (*json* (format t "~A~%" (if info (service-json info) "null")) (if info 0 1))
        (info (format t "~&~A~%" fq) (print-service info) 0)
        (t (format t "~&Not found: ~A~%" fq) 1)))))

;;; --- interfaces ------------------------------------------------------------

(defun interface-json (nif)
  (format nil "{~A:~A,~A:~A,~A:~A,~A:~A}"
          (jstr "name") (jstr (0conf:net-interface-name nif))
          (jstr "index") (or (0conf:net-interface-index nif) "null")
          (jstr "ipv4") (let ((v4 (0conf:net-interface-ipv4 nif)))
                          (if v4 (jstr (0conf:format-ipv4 v4)) "null"))
          (jstr "has_v6") (if (0conf:net-interface-has-v6 nif) "true" "false")))

(defun cmd-interfaces (opts)
  (let* ((all (gethash "all" opts))
         (ifs (0conf:list-interfaces :include-loopback (and all t)
                                     :multicast-only (not all))))
    (cond
      (*json* (format t "[~{~A~^,~}]~%" (mapcar #'interface-json ifs)) 0)
      (t (format t "~&~8A ~6A ~16A ~A~%" "NAME" "INDEX" "IPV4" "IPV6")
         (dolist (nif ifs)
           (format t "~8A ~6A ~16A ~A~%"
                   (0conf:net-interface-name nif)
                   (or (0conf:net-interface-index nif) "-")
                   (let ((v4 (0conf:net-interface-ipv4 nif)))
                     (if v4 (0conf:format-ipv4 v4) "-"))
                   (if (0conf:net-interface-has-v6 nif) "yes" "-")))
         0))))

;;; --- publish ---------------------------------------------------------------

(defun parse-txt (kvs)
  "A list of \"k=v\" / bare \"k\" strings -> the alist MAKE-SERVICE-INFO wants."
  (mapcar (lambda (kv)
            (let ((eq (position #\= kv)))
              (if eq (cons (subseq kv 0 eq) (subseq kv (1+ eq))) (cons kv nil))))
          kvs))

(defun cmd-publish (pos opts)
  (destructuring-bind (&optional type name port &rest ignore) pos
    (declare (ignore ignore))
    (unless (and type name port)
      (cli-error "usage: ~A publish <type> <name> <port> [--txt k=v]... [--subtype s]..." *program*))
    (let ((port-n (or (ignore-errors (parse-integer port))
                      (cli-error "port must be a number: ~A" port)))
          (info nil)
          (responder (0conf:make-responder)))
      (setf info (0conf:make-service-info
                  :type (ensure-local type) :name name :port port-n
                  :txt (parse-txt (reverse (gethash "txt" opts)))
                  :subtypes (reverse (gethash "subtype" opts))
                  :host (or (gethash "host" opts) (0conf:default-host-name))))
      (unwind-protect
           (progn
             (0conf:start-responder
              responder
              :socket (and *interface* (0conf:make-mdns-socket :interface (iface-arg) :family *family*)))
             (0conf:register-service responder info :probe (not (gethash "no-probe" opts)))
             (if *json*
                 (format t "~A~%" (service-json info))
                 (format t "~&Publishing ~A~%  type ~A  port ~D~@[  host ~A~]~%  (Ctrl-C to stop)~%"
                         (sanitize (0conf:service-instance-name info))
                         (0conf:service-info-type info) port-n
                         (0conf:service-info-host info)))
             (finish-output)
             (handler-case (loop (sleep 1))
               (sb-sys:interactive-interrupt () nil)))
        (ignore-errors (0conf:unregister-service responder info))    ; goodbye
        (ignore-errors (0conf:stop-responder responder))
        (unless *json* (format t "~&Stopped.~%")))
      0)))

;;; --- monitor (live view) ---------------------------------------------------

(defstruct seen info first last)        ; a discovered instance + first/last time

(defun age-string (e now)
  (let ((secs (max 0 (round (/ (- now (seen-first e)) internal-time-units-per-second)))))
    (cond ((< secs 60) (format nil "~Ds" secs))
          ((< secs 3600) (format nil "~Dm" (floor secs 60)))
          (t (format nil "~Dh" (floor secs 3600))))))

(defun render-dashboard (seens)
  (let ((by-type (make-hash-table :test 'equal))
        (now (get-internal-real-time)))
    (dolist (e seens) (push e (gethash (0conf:service-info-type (seen-info e)) by-type)))
    (clear-home)
    (format t "~A monitor — ~D service~:P across ~D type~:P   (Ctrl-C to quit)~2%"
            *program* (length seens) (hash-table-count by-type))
    (if (null seens)
        (format t "  discovering services…~%")
        (dolist (ty (sort (hash-keys by-type) #'string<))
          (format t "~A~%" (bold ty))
          (dolist (e (sort (copy-list (gethash ty by-type)) #'string-lessp
                           :key (lambda (e) (0conf:service-info-name (seen-info e)))))
            (format t "    ~30A ~22A ~A~%"
                    (fit (sanitize (0conf:service-info-name (seen-info e))) 30)
                    (host-port (seen-info e))
                    (age-string e now)))
          (terpri)))
    (finish-output)))

(defun output-snapshot (seens)
  (let ((infos (mapcar #'seen-info seens)))
    (cond
      (*json* (format t "~A~%" (services-json infos)))
      (infos (format t "~&~D service~:P:~2%" (length infos))
             (dolist (i (sort (copy-list infos) #'string-lessp :key #'0conf:service-info-name))
               (print-service i) (terpri)))
      (t (format t "~&No services found.~%")))
    (finish-output)))

(defun log-event (sign info-or-name)
  "Streaming +/- line for the non-TTY monitor."
  (if (stringp info-or-name)
      (format t "~C ~A~%" sign (sanitize info-or-name))
      (format t "~C ~A  ~A  ~A~%" sign (0conf:service-info-type info-or-name)
              (sanitize (0conf:service-info-name info-or-name)) (host-port info-or-name)))
  (finish-output))

(defun cmd-monitor (opts)
  (let* ((once (gethash "once" opts))
         (for-secs (let ((f (gethash "for" opts)))
                     (and f (or (ignore-errors (float (read-from-string f)))
                                (cli-error "--for needs a number of seconds")))))
         (type-filter (let ((tf (gethash "type" opts))) (and tf (ensure-local tf))))
         (mode (cond ((or once *json*) :once) (*ansi* :dashboard) (t :stream)))
         (responder (0conf:make-responder))
         (services (make-hash-table :test 'equal))
         (browsers (make-hash-table :test 'equal))
         (lock (bordeaux-threads:make-lock "monitor"))
         (running t)
         (start (get-internal-real-time))
         (deadline (and for-secs (+ start (round (* for-secs internal-time-units-per-second)))))
         (once-deadline (and (eq mode :once)
                             (+ start (round (* *timeout* internal-time-units-per-second))))))
    (labels ((put (i)
               (let ((name (0conf:service-instance-name i)) (now (get-internal-real-time)))
                 (bordeaux-threads:with-lock-held (lock)
                   (let ((e (gethash name services)))
                     (cond (e (setf (seen-info e) i (seen-last e) now))
                           (t (setf (gethash name services) (make-seen :info i :first now :last now))
                              (when (eq mode :stream) (log-event #\+ i))))))))
             (del (n)
               (bordeaux-threads:with-lock-held (lock)
                 (when (and (eq mode :stream) (gethash n services)) (log-event #\- n))
                 (remhash n services)))
             (ensure-browser (ty)
               (bordeaux-threads:with-lock-held (lock)
                 (unless (gethash ty browsers)
                   (setf (gethash ty browsers)
                         (0conf:browse-services responder ty
                                                :on-add #'put :on-update #'put :on-remove #'del)))))
             (snapshot ()
               (bordeaux-threads:with-lock-held (lock)
                 (loop for e being the hash-values of services collect e)))
             (expired-p ()
               (or (not running)
                   (and deadline (>= (get-internal-real-time) deadline))
                   (and once-deadline (>= (get-internal-real-time) once-deadline))))
             (nap (secs)
               (loop repeat (max 1 (round (/ secs 0.2)))
                     while (not (expired-p)) do (sleep 0.2))))
      (unwind-protect
           (progn
             (0conf:start-responder
              responder
              :socket (and *interface* (0conf:make-mdns-socket :interface (iface-arg) :family *family*)))
             (when (eq mode :dashboard) (hide-cursor) (clear-home))
             ;; seed browsers
             (if type-filter
                 (ensure-browser type-filter)
                 (progn
                   (dolist (ty +well-known-types+) (ensure-browser ty))
                   (bordeaux-threads:make-thread
                    (lambda ()
                      (loop while running do
                        (dolist (ty (ignore-errors
                                     (0conf:enumerate-service-types :timeout 1.5)))
                          (ensure-browser ty))
                        (loop repeat 16 while running do (sleep 0.25))))
                    :name "0conf-type-poll")))
             ;; run
             (handler-case
                 (ecase mode
                   (:once (nap most-positive-fixnum)          ; until once-deadline
                          (output-snapshot (snapshot)))
                   (:dashboard (loop until (expired-p)
                                     do (render-dashboard (snapshot)) (nap 1.0)))
                   (:stream (loop until (expired-p) do (nap 0.3))))
               (sb-sys:interactive-interrupt ()
                 (setf running nil)
                 (when (eq mode :once) (output-snapshot (snapshot))))))
        ;; Fast teardown: signal the poll thread, stop the responder (which
        ;; releases the socket and stops answering), and restore the cursor.  We
        ;; deliberately do NOT join the dozens of per-type browser threads — that
        ;; would take tens of seconds; TOPLEVEL's `:abort t` reaps them at exit.
        (setf running nil)
        (ignore-errors (0conf:stop-responder responder))
        (when (eq mode :dashboard) (show-cursor) (terpri)))))
  0)

;;; --- option parsing --------------------------------------------------------

(defparameter +flag-specs+
  '(("--json" . :bool) ("--all" . :bool) ("--once" . :bool) ("--no-probe" . :bool)
    ("--version" . :bool) ("-V" . :bool) ("--help" . :bool) ("-h" . :bool)
    ("-6" . :bool) ("--ipv6" . :bool) ("-4" . :bool) ("--ipv4" . :bool)
    ("-i" . :value) ("--interface" . :value) ("--timeout" . :value)
    ("--for" . :value) ("--type" . :value) ("--host" . :value) ("--color" . :value)
    ("--txt" . :repeat) ("--subtype" . :repeat)))

(defun canonical (flag)
  (cond ((member flag '("-6" "--ipv6") :test #'string=) "ipv6")
        ((member flag '("-4" "--ipv4") :test #'string=) "ipv4")
        ((member flag '("-i" "--interface") :test #'string=) "interface")
        ((member flag '("-V" "--version") :test #'string=) "version")
        ((member flag '("-h" "--help") :test #'string=) "help")
        (t (string-left-trim "-" flag))))

(defun flag-value (name inline rest)
  "The value for a :value/:repeat flag NAME: its inline part or the next token.
Errors if missing or itself option-shaped."
  (let ((v (or inline (and rest (first rest)))))
    (when (or (null v) (zerop (length v))
              (and (null inline) (> (length v) 0) (char= (char v 0) #\-)))
      (cli-error "option ~A needs a value" name))
    v))

(defun parse-args (argv)
  "Returns (values positionals opts).  OPTS maps a canonical flag name to T, a
value string, or (for repeats) a list.  Signals CLI-ERROR on bad usage."
  (let ((opts (make-hash-table :test 'equal))
        (pos '())
        (no-more nil)
        (rest argv))
    (loop while rest
          for tok = (pop rest)
          do (cond
               (no-more (push tok pos))
               ((string= tok "--") (setf no-more t))
               ((and (> (length tok) 1) (char= (char tok 0) #\-))
                (let* ((eq (position #\= tok))
                       (name (if eq (subseq tok 0 eq) tok))
                       (inline (and eq (subseq tok (1+ eq))))
                       (spec (cdr (assoc name +flag-specs+ :test #'string=))))
                  (unless spec (cli-error "unknown option ~A" name))
                  (ecase spec
                    (:bool (when inline (cli-error "option ~A takes no value" name))
                           (setf (gethash (canonical name) opts) t))
                    (:value (setf (gethash (canonical name) opts) (flag-value name inline rest))
                            (unless inline (pop rest)))
                    (:repeat (push (flag-value name inline rest) (gethash (canonical name) opts))
                             (unless inline (pop rest))))))
               (t (push tok pos))))
    (values (nreverse pos) opts)))

(defun compute-terminal (opts)
  "Set *ANSI* / *COLOR* from --color, NO_COLOR, --json, and whether stdout is a TTY."
  (let* ((mode (let ((c (gethash "color" opts)))
                 (cond ((null c) :auto)
                       ((string= c "always") :always)
                       ((string= c "never") :never)
                       ((string= c "auto") :auto)
                       (t (cli-error "--color must be auto, always, or never")))))
         (tty (interactive-stream-p *standard-output*))
         (want (case mode (:always t) (:never nil) (:auto tty))))
    (setf *ansi* (and want (not *json*))
          *color* (and *ansi* (or (eq mode :always) (not (sb-ext:posix-getenv "NO_COLOR")))))))

;;; --- usage / dispatch ------------------------------------------------------

(defun usage (&optional (stream *standard-output*))
  (format stream "~&~A ~A — browse, resolve, monitor, and publish mDNS / DNS-SD ~
                  services on the local network.~2%~
                  Usage:~%~
                  ~2T~A browse [<type>]            list service types, or instances of a type~%~
                  ~2T~A monitor                    live view of all services (--once, --for S, --type T)~%~
                  ~2T~A resolve <instance>         resolve one instance to host / port / TXT~%~
                  ~2T~A publish <type> <name> <port>   advertise a service until Ctrl-C~%~
                  ~2T~A interfaces                 list usable network interfaces~%~
                  ~2T~A help | --version~2%~
                  Options:~%~
                  ~2T-i, --interface <if>     pin the egress interface: a name (en0), a v4~%~
                  ~2T                         dotted-quad, or a v6 index~%~
                  ~2T--timeout <secs>         query window for browse/resolve/monitor --once~%~
                  ~2T--json                   machine-readable output~%~
                  ~2T--color auto|always|never~%~
                  ~2T-6/--ipv6, -4/--ipv4     address family for browse/resolve~%~
                  ~2T--txt k=v, --subtype s   (publish)   --all (interfaces)~%"
          *program* +version+
          *program* *program* *program* *program* *program* *program*))

(defun dispatch (cmd pos opts)
  (cond
    ((string= cmd "browse")     (cmd-browse pos))
    ((string= cmd "monitor")    (cmd-monitor opts))
    ((string= cmd "resolve")    (cmd-resolve pos))
    ((string= cmd "publish")    (cmd-publish pos opts))
    ((string= cmd "interfaces") (cmd-interfaces opts))
    ((string= cmd "help")       (usage) 0)
    (t (format *error-output* "~&~A: unknown command ~S~%~%" *program* cmd)
       (usage *error-output*)
       2)))

(defun main (&optional (argv (rest sb-ext:*posix-argv*)))
  "Parse ARGV, bind the global options, and dispatch.  Returns a Unix exit code."
  (handler-case
      (multiple-value-bind (pos opts) (parse-args argv)
        (cond
          ((gethash "version" opts) (format t "~A ~A~%" *program* +version+) 0)
          ((gethash "help" opts) (usage) 0)
          ((null (first pos)) (usage *error-output*) 2)
          (t (let ((*json* (and (gethash "json" opts) t))
                   (*interface* (gethash "interface" opts))
                   (*family* (if (gethash "ipv6" opts) :ipv6 :ipv4))
                   (*timeout* (let ((ts (gethash "timeout" opts)))
                                (if ts
                                    (or (ignore-errors (float (read-from-string ts)))
                                        (cli-error "--timeout needs a number of seconds"))
                                    3.0))))
               (compute-terminal opts)
               (dispatch (first pos) (rest pos) opts)))))
    (cli-error (e)
      (format *error-output* "~&~A: ~A~%" *program* e)
      2)))

(defun toplevel ()
  "Executable entry point: run MAIN, flush, and hard-exit with its code (130 on
Ctrl-C).  :ABORT T exits immediately rather than waiting on lingering responder /
browser threads (which a graceful exit would join); we flush first so no output
is lost."
  (let ((code (handler-case (or (main) 0)
                (sb-sys:interactive-interrupt () 130)
                (error (e) (format *error-output* "~&~A: ~A~%" *program* e) 1))))
    (ignore-errors (finish-output *standard-output*))
    (ignore-errors (finish-output *error-output*))
    (sb-ext:exit :code code :abort t)))
