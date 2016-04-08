(ql:quickload :elf)
(ql:quickload :cffi)
(ql:quickload :iolib)
(defpackage #:asmtools-pkg
  (:use :cl :asdf :cffi :iolib))

(in-package :asmtools-pkg)

(asdf:defsystem :asmtools
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "asmtools")))
	

