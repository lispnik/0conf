;;;; test/cache-tests.lisp — deterministic clock via an explicit NOW (=1000).

(in-package #:0conf/test)

(in-suite 0conf-tests)

(defun a-rec (name ip &key (ttl 120) cache-flush)
  (make-instance 'a-record :name name :address (parse-ipv4 ip)
                           :ttl ttl :cache-flush cache-flush))

(defun live-a (cache name now)
  (cache-get cache name +type-a+ +class-in+ now))

(test cache-add-and-get
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1") now)
    (let ((live (live-a c "host.local" now)))
      (is (= 1 (length live)))
      (is (equalp (parse-ipv4 "10.0.0.1") (a-address (first live)))))))

(test cache-multiple-addresses-coexist
  ;; Two A records for one name (multi-homed host) both live until flushed.
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1") now)
    (cache-add c (a-rec "host.local" "10.0.0.2") now)
    (is (= 2 (length (live-a c "host.local" now))))))

(test cache-flush-supersedes
  ;; A cache-flush record removes differing records of the same name/type
  ;; that were received more than a second ago (RFC 6762 §10.2).
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1") now)
    (cache-add c (a-rec "host.local" "10.0.0.2") now)
    (cache-add c (a-rec "host.local" "10.0.0.9" :cache-flush t) (+ now 2))
    (let ((live (live-a c "host.local" (+ now 2))))
      (is (= 1 (length live)))
      (is (equalp (parse-ipv4 "10.0.0.9") (a-address (first live)))))))

(test cache-flush-defers-recent
  ;; §10.2: records received within the last second are NOT flushed, so a
  ;; multi-packet response (one answer split across datagrams) survives.
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1") now)
    (cache-add c (a-rec "host.local" "10.0.0.2") now)
    ;; flush arrives in the same second -> the earlier two are spared
    (cache-add c (a-rec "host.local" "10.0.0.9" :cache-flush t) now)
    (is (= 3 (length (live-a c "host.local" now))))))

(test cache-goodbye-removes
  ;; ttl 0 is an mDNS goodbye.
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1") now)
    (cache-add c (a-rec "host.local" "10.0.0.1" :ttl 0) now)
    (is (null (live-a c "host.local" now)))))

(test cache-refresh-threshold
  ;; cache-needs-refresh-p fires once a live entry passes 80% of its lifetime.
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1" :ttl 100) now)   ; expires at 1100
    (is (not (0conf::cache-needs-refresh-p c now)))              ; 0% elapsed
    (is (not (0conf::cache-needs-refresh-p c (+ now 79))))       ; 79%
    (is (0conf::cache-needs-refresh-p c (+ now 80)))             ; 80% -> refresh
    (is (not (0conf::cache-needs-refresh-p c (+ now 200))))))    ; expired -> nothing to refresh

(test cache-expiry
  (let ((c (make-cache)) (now 1000))
    (cache-add c (a-rec "host.local" "10.0.0.1" :ttl 120) now)
    (is (= 1 (length (live-a c "host.local" now))))
    ;; 200s later the 120s record is expired-out.
    (is (= 1 (cache-expire c (+ now 200))))
    (is (null (cache-all c (+ now 200))))))
