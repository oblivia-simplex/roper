(ql:quickload :cffi)
(defpackage :cl-unicorn
  (:use :common-lisp :cffi))

(in-package :cl-unicorn)

(define-foreign-library libunicorn
  (:unix (:or "libunicorn.so.1" "libunicorn.so"))
  (t (:default "libunicorn")))

(use-foreign-library libunicorn)
