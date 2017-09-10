(in-package :ropush)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;                        Test Functions                      ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun test2 (script)
  (with-stacks (:gadget :int :bool :string :code :exec)
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
	`(:list . ((:string . "already in a list") (:string . "in a list too")))
	`(:op . ,!exec-rot+)
	`(:op . ,!store-code)
	`(:string . "am i code?")
	`(:op . ,!int-rot+)
	`(:op . ,!int->list)
	`(:op . ,!store-code)
	`(:op . ,!string-dup)
	`(:op . ,!string-len)
	`(:string . "done")))

