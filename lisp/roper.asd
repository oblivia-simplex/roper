(ql:quickload :elf)
(ql:quickload :cffi)
(ql:quickload :iolib)
(defpackage #:roper-pkg
  (:use :cl :asdf :cffi :iolib))

(in-package :roper-pkg)

(asdf:defsystem :roper
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "roper")))
	

