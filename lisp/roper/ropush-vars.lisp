(in-package :ropush)

(defvar $$push)
(defvar $$pop)
(defvar $$peek)
(defvar $stacks)
(defvar $counter)
(defvar $unicorn)
(defvar $halt)

(export '*operations*)
(defvar *operations* ())

(defparameter *debug* t)

;; the list provided in ropush-params is meant to be editable.
;; this list furnishes the defaults.
(export '*stack-types*)
(defparameter *stack-types* '(:input!
			      :output!
			      :gadget
			      :bool
			      :int
			      :list
			      :exec
			      :op
			      :ratio
			      :string
			      :code))

(export '*immutable-stacks*)
(defparameter *immutable-stacks* '(:input!))

(defun mk-unpacker (type)
  (lambda (lst)
    (mapcar #'$push
	    (remove-if-not (lambda (y) (eq (car y) type))
			   lst))))
