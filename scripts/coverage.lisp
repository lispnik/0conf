;;;; scripts/coverage.lisp — generate an sb-cover test-coverage report.
;;;;
;;;; Recompiles 0conf (only) with coverage instrumentation, runs the FiveAM
;;;; suite over it, and writes an HTML report to coverage/.  Run from the repo
;;;; root:  sbcl --non-interactive --load scripts/coverage.lisp

(require :sb-cover)

;; Instrument on the next compile.
(declaim (optimize sb-cover:store-coverage-data))

;; Force-recompile just 0conf's own files (deps stay uninstrumented).
;; 0conf/cli too: the test system depends on it, so it lands in the report either
;; way once its fasl is stale — force it so the figure doesn't depend on cache state.
(asdf:load-system :0conf :force t)
(asdf:load-system :0conf/cli :force t)

;; Compile/run the tests normally against the instrumented library.
(asdf:load-system :0conf/test)
(let ((0conf::*response-delay* nil))
  (fiveam:run! '0conf/test::0conf-tests))

;; Emit the report.
(ensure-directories-exist "coverage/")
(sb-cover:report "coverage/")

;; Stop instrumenting.
(declaim (optimize (sb-cover:store-coverage-data 0)))

(format t "~&Coverage report written to coverage/cover-index.html~%")
