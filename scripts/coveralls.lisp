;;;; scripts/coveralls.lisp — run the suite under sb-cover and post the result
;;;; to coveralls.io via cl-coveralls.
;;;;
;;;;   COVERALLS=1 sbcl --non-interactive --load scripts/coveralls.lisp
;;;;
;;;; WITH-COVERALLS is inert unless the COVERALLS env var is set and non-empty,
;;;; so an accidental run just runs the tests.  Outside a recognized CI service
;;;; it forces a dry run — the JSON is printed, nothing is uploaded — which is
;;;; how you check this locally.  In GitHub Actions it POSTs, and needs
;;;; COVERALLS_REPO_TOKEN in the environment (a repo secret; never in-tree).
;;;;
;;;; cl-coveralls is not in ocicl.csv: it pulls ~70 systems (dexador, iolib,
;;;; cffi, ironclad...) and only this script wants them, so the library's
;;;; lockfile stays lean and CI installs it on demand.  Locally:
;;;;   ocicl install cl-coveralls
;;;;
;;;; For a local HTML report instead, use scripts/coverage.lisp.

(asdf:load-system :cl-coveralls)
(asdf:load-system :0conf/test)

;; WITH-COVERALLS force-reloads 0conf instrumented, runs the body against it,
;; then reports.  EXCLUDE keeps the upload to the library sources — the sb-cover
;; run also instruments the test files, which are not the thing being measured.
(let ((ok (coveralls:with-coveralls (:exclude (list "test/" "scripts/" "doc/"))
            ;; cl-coveralls force-loads only the primary system named by the .asd
            ;; file (0conf).  0conf/cli is instrumented anyway — the test system
            ;; depends on it — so force it here, inside the body where
            ;; instrumentation is on, and the report stops depending on whether a
            ;; cached fasl happened to be stale.
            (asdf:load-system :0conf/cli :force t)
            (let ((0conf::*response-delay* nil))   ; no artificial response jitter
              (fiveam:run! '0conf/test::0conf-tests)))))
  (unless ok
    (format *error-output* "~&Tests failed.~%")
    (uiop:quit 1)))
