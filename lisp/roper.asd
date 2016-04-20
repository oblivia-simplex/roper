(ql:quickload :elf)
(ql:quickload :cffi)
(ql:quickload :iolib)
(ql:quickload :usocket)
(defpackage #:roper-pkg
  (:use :cl :asdf :cffi ))

(in-package :roper-pkg)

(asdf:defsystem :roper
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "aux")
               (:file "roper")))
	

