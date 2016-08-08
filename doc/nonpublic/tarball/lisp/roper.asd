(ql:quickload :elf)
(ql:quickload :cffi)
(ql:quickload :iolib)
(ql:quickload :usocket)
(defpackage #:roper
  (:use :cl :asdf :cffi ))

(in-package :roper)

(asdf:defsystem :roper
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "aux")
               (:file "phylo")))
	

