(option primus-lisp-add $prefix)
(option primus-lisp-load
  posix
  memcheck-malloc
  limit-malloc
  taint-sources
  sensitive-sinks)

(option primus-promiscuous-mode)
(option primus-greedy-scheduler)
(option primus-limit-max-length 4096)

(option cwe-checker-emulation)
