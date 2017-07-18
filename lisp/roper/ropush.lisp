;bool pushGP variant for ROPER
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
			       $counter (quote ,name)
			       ;(list ,@arglist)
			       #\Tab
			       $stacks #\Tab __res)
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

;; too noisy to make this a defstackfn
(defun $exec (item)
  (case (type-of item)
    ((operation) ($call-op item))
    ((cons) ($push item))
    (:otherwise (print 'what-happened?))))

;; modify this so that it can handle symbols denoting lists for stack-keywords,
;; as well as literal lists (as it exclusively does now)
(defmacro with-stacks (stack-keywords &rest body)
  `(let (($counter 0)
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

(defparameter *stack-types* '(:gadget
			      :int
			      :pointer
			      :dword
			      :bool
			      :exec
			      :string
			      :code))

(defun test (things)
  (with-stacks #.*stack-types*
    (loop for thing in things do
	 (funcall $push thing))
    (format t "Stacks are now: ~S~%" $stacks)))

(defstruct (operation (:conc-name op-))
  (sig () :type (or null (cons keyword)))
  (ret () :type (or null (cons keyword)))
  (func))

(defun %$call-op (op)
  (let ((args (mapcar #'$peek (op-sig op))))
    (unless (some #'null args)
      (let ((args (mapcar #'$pop (op-sig op))))
	(mapcar
	 (lambda (x y)
	   ($push (cons x y)))
	 (op-ret op)
	 (apply (op-func op) args))))))
					;($push
	; (cons (op-ret op)
	;       (apply (op-func op) args)))))))
      ;; do the rest here

(defstackfn $call-op (op)
  (%$call-op op))

(defstackfn $load-exec (exec-stack)
  (setf (cdr (assoc :exec $stacks)) exec-stack))


;; a unit will be either a type.val pair, or an op.
;(defstruct unit
;  (kind nil :type (or null keyword))
					;  (body
;; Some standard functions
(defmacro def-generic-op (suffix param-arity ret-arity arglist &rest body)
  (cons 'progn
	(loop for type in *stack-types* collect
	     `(defparameter ,(intern (format nil "!~A-~A" type suffix))
		(make-operation
		 :sig (quote ,(loop for i below param-arity collect type))
		 :ret (quote ,(loop for i below ret-arity collect type))
		 :func (lambda ,arglist
			 (progn
			   ,@body)))))))

(def-generic-op rot 3 3
		(x y z)
		(list y x z))

(def-generic-op swap 2 2
		(x y)
		(list x y))

(def-generic-op dup 1 2
		(x)
		(list x x))


;;; testing
;;;


(defparameter !plus (make-operation
		:sig '(:int :int)
		:ret '(:string)
		:func (lambda (x y)
			(list (format nil "The answer is ~D" (+ x y))))))

(defparameter !strlen (make-operation
		       :sig '(:string)
		       :ret '(:int)
		       :func (lambda (x) (list (length x)))))


(defparameter !store-code (make-operation
			   :sig '(:exec)
			   :ret '(:code)
			   :func #'list))

(defparameter !load-code (make-operation
			  :sig '(:code)
			  :ret '(:exec)
			  :func #'list))

(defun test2 (script)
  (with-stacks (:gadget :int :bool :string :code :exec)
    ($clear)
    (eval script)))

(defun test3 (exec-stack)
  (with-stacks #.*stack-types*
    ($clear)
    (mapcar #'$exec exec-stack)))

(defun test4 (exec-stack)
  (with-stacks #.*stack-types*
    ($clear)
    ($load-exec exec-stack)
    (loop while (cdr (assoc :exec $stacks)) do
	 ($exec ($pop :exec)))))

(defparameter script1
  '(progn
      ($push `(:string . "goodbye, world!"))
      ($push `(:string . "hello, world!"))
      ($call-op !strlen)
      ($call-op !strlen)
      ($call-op !plus)
      ($call-op !plus)
      ($push `(:int . 32))
      ($push `(:int . 16))
      ($call-op !int-swap)
      ($push '(:int . 999))
      ($call-op !int-rot)
      ($call-op !string-dup)))

(defparameter exec-stack-1
  (list `(:string . "hello")
	`(:int . 1000)
	`(:int . 1)
	`(:bool . t)
	!int-dup
	!exec-dup
	!exec-rot
	!store-code
	`(:string . "am i code?")
	!int-rot
	!store-code
	!string-dup
	!strlen
	`(:string . "done")))
