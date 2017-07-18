;; pushGP variant for ROPER
;; individual isn't a ROP chain, but a ROP chain builder

;; data representation:
;; cons pairs. first element is keyword indicating stack, second is data
;; e.g. (:gadget . gad)
(in-package :ropush)


(defvar $$push)
(defvar $$pop)
(defvar $$peek)
(defvar $stacks)
(defvar $counter)

(defparameter *debug* t)

(defmacro defstackfn (name arglist &rest body)
  `(defun ,name ,arglist
     (let ((__res (progn
		    ,@body)))
       ,(if *debug* `(progn
		       (format t "[~D] ~A ~A~S ~A-> ~S~%"
			       $counter (quote ,name) #\Tab $stacks
			       #\Tab __res)
		       (incf $counter)))
       __res)))

(defstackfn $push (typ.val)
  (funcall $$push typ.val))

(defstackfn $peek (typ)
  (funcall $$peek typ))

(defstackfn $pop (typ)
  (funcall $$pop typ))

(defstackfn $clear ()
  (mapcar (lambda (x) (setf (cdr x) nil)) $stacks))


(defmacro with-stacks (stack-keywords &rest body)
  `(let (,(if *debug* `($counter 0))
	 ($stacks
	  (quote ,(loop for key in stack-keywords
		    collect
			`(,key . ())))))
     (labels (($stackf (key)
		(cdr (assoc key $stacks)))
	      ((setf $stackf) (new-value key)
		(setf (cdr (assoc key $stacks))
		      (cons new-value (cdr (assoc key $stacks))))))
       (let (($$push
	      (lambda (type.val)
		(setf ($stackf (car type.val)) (cdr type.val))))
	     ($$pop
	      (lambda (type)
		(pop (cdr (assoc type $stacks)))))
	     ($$peek
	      (lambda (type)
		(cdr (assoc type $stacks)))))
	 (progn
	 `(declare (ignore $push $pop))
	 ,@body)
	 $stacks))))

#.(defparameter *stack-types* '(:gadget
				:int
				:pointer
				:dword
				:exec
				:code))

(defun test (things)
  (with-stacks #.*stack-types*
    (loop for thing in things do
	 (funcall $push thing))
    (format t "Stacks are now: ~S~%" $stacks)))

(defstruct (operation (:conc-name op-))
  (sig ()  :type (or null (cons keyword)))
  (ret nil :type (or null keyword))
  (func))

(defun $call-op (op)
  (let ((args (mapcar #'$peek (op-sig op))))
    (unless (some #'null args)
      (let ((args (mapcar #'$pop (op-sig op))))
	($push
	 (cons (op-ret op)
	       (apply (op-func op) args)))))))
      ;; do the rest here

;; a unit will be either a type.val pair, or an op.
;(defstruct unit
;  (kind nil :type (or null keyword))
;  (body 

(defun test2 ()
  (let ((!strlen (make-operation
		  :sig '(:string)
		  :ret :int
		  :func #'length)))
    (with-stacks (:int :string :boolean)
      ($clear)
      ($push `(:string . "goodbye, world!"))
      ($push `(:string . "hello, world!"))
      ($call-op !strlen))))
      
