(in-package :ropush)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;                        Test Functions                      ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun test2 (script)
  (with-stacks (:gadget :int :bool :string :womb :exec)
    ($clear)
    (eval script)))

(defun test3 (exec-stack)
  (with-stacks #.*stack-types*
    ($clear)
    (mapcar #'$exec exec-stack)))

(defparameter script1
  '(progn
      ($push `(:string . "goodbye, world!"))
      ($push `(:string . "hello, world!"))
      ($call-op !string-len)
      ($call-op !string-len)
      ($call-op !int-string-plus)
      ($call-op !int-string-plus)
      ($push `(:int . 32))
      ($push `(:int . 16))
      ($call-op !int-swap)
      ($push '(:int . 999))
      ($call-op !int-rot+)
      ($call-op !string-dup)))

(defparameter exec-stack-1
  (list `(:string . "hello")
	`(:int . 1000)
	`(:int . 1)
	`(:bool . t)
	`(:op . ,!int-dup)
	`(:op . ,!exec-dup)
	`(:op . ,!exec-over)
	`(:op . ,!store-womb)
	`(:string . "am i womb?")
	`(:op . ,!int-rot+)
	`(:op . ,!store-womb)
	`(:op . ,!string-dup)
	`(:op . ,!string-len)
	`(:string . "done")))

(defparameter exec-stack-2
  (list (cons :int 3)
	(cons :int 4)
	(cons :int 5)
	(cons :op !int-plus)
	(cons :op !int-dup)
	(cons :op !int-rot+)))
