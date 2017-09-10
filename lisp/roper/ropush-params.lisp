(in-package :ropush)

(defparameter *constant-directory*
  #P"/home/oblivia/src/lisp/roper/ropush-constants/")
  
(defparameter *stack-types* '(:gadget
			      :int
			      :pointer
			      :dword
			      :bool
			      :list
			      :exec
			      :op
			      :ratio
			      :string
			      :code))

;; EXAMPLE VALUE
(defparameter *elf* (elf:read-elf "/home/oblivia/Projects/roper/data/tomato-RT-AC3200-ARM-132-AIO-httpd"))

(defparameter *typed-ropush-minlens*
  `((:gadget 4)
    (:dword 12)
    (:int 3)))
