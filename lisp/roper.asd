(ql:quickload :elf)
(ql:quickload :cffi)
(ql:quickload :usocket)
(defpackage #:roper-pkg
  (:use :cl :asdf :cffi :usocket))

(in-package :roper-pkg)

(asdf:defsystem :roper
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "roper")))
	

