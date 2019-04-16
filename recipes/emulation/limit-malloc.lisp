;; taken from
;;https://github.com/BinaryAnalysisPlatform/bap-recipes/blob/master/primus-checks/limit-malloc.lisp
;; up to 4 Mb each chunk, up to 128 Mbytes total

(defmethod init ()
  (set *malloc-max-chunk-size* (* 4 1024 1024))
  (set *malloc-guard-edges* 0)
  (set *malloc-max-arena-size* (* 32 *malloc-max-chunk-size*))
  (set *malloc-arena-start* brk)
(set *malloc-zero-sentinel* 0))
