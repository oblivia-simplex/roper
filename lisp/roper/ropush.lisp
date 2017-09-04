;: ushGP variant for ROPER
;; individual isn't a ROP chain, but a ROP chain builder

;; data representation:
;; cons pairs. first element is keyword indicating stack, second is data
;; e.g. (:gadget . gad)
(in-package :ropush)

(defparameter *operations* '())

(defstruct (operation (:conc-name op-))
  (name 'unnamed-operation :type symbol)
  (sig () :type (or null (cons keyword)))
  (ret () :type (or null (cons keyword)))
  (func))

(defun mangle-symbols (syms)
  (let ((i 0)
	(mangs ()))
    (loop for sym in syms do
	 (push (intern (format nil "_~A_~D" sym i)) mangs)
	 (incf i))
    mangs))
	 

(defmacro encaps-fn (sig fn)
  "Takes a function and a signature list, then returns a new function
that returns the value of the old function, wrapped in a list"
  (let ((mang (mangle-symbols sig)))
    `(lambda ,mang
       (list (apply ,fn `(,,@mang)))))
  )

(defmacro defop (name &key sig ret func)
  `(progn
     (defparameter ,name (make-operation
			  :name (quote ,name)
			  :sig (quote ,sig)
			  :ret (quote ,ret)
			  :func ,func))
     (push ,name *operations*)))

(defun repr (unit)
  (when unit
    (if (listp unit)
	(let ((val-str (if (eq (car unit) :op)
			   (format nil "~A" (op-name (cdr unit)))
			   (format nil "~A" unit))))
	  val-str)
	(format nil "~A" unit))))

(defun repr-stack-tops (stacks)
  (let ((fstr (make-array '(0) :element-type 'base-char
			  :fill-pointer 0
			  :adjustable t)))
    (with-output-to-string (s fstr)
      (loop for stack in stacks do
	   (format s "  ~A: ~A [top of ~D]~%" (car stack) (repr (cadr stack)) (length (cdr stack)))))
    fstr))

(defun abridge-to-str (lst &optional (maxlen 4))
  (if (and (listp lst) (listp (cdr lst)))
      (if (< (length lst) maxlen)
	  (format nil "~S" lst)
	  (format nil "(~S ... ) [~D elements]"
		  (car lst)
		  (length lst)))
      (format nil "~S" lst)))

(defmacro defstackfn (name arglist &rest body)
  `(defun ,name ,arglist
     (let ((__res (progn
		    ,@body)))
       ,(if *debug* `(progn
		       (format t "[~D] ~A ~A -> ~A~%~A~%"
			       $counter
			       (quote ,name)
			       (abridge-to-str (list ,@arglist))
			       (abridge-to-str __res)
			       (repr-stack-tops $stacks)
			       )
		       (incf $counter)))
       __res)))

(defstackfn $push (typ.val)
  (funcall $$push typ.val))

(defstackfn $peek (typ)
  (funcall $$peek typ))

(defstackfn $pop (typ)
  (funcall $$pop typ))

(defstackfn $pop-keep-types (typ)
  (funcall $$pop typ :keep-types t))

(defstackfn $clear ()
  (mapcar (lambda (x) (setf (cdr x) nil)) $stacks))

;; too noisy to make this a defstackfn
(defun $exec (item)
  (if (eq (car item) :op)
      ($call-op (cdr item))
      ($push item)))

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
	      (lambda (type &key keep-types)
		(if keep-types
		    (cons type (pop (cdr (assoc type $stacks))))
		    (pop (cdr (assoc type $stacks))))))
	     ($$peek
	      (lambda (type)
		(cdr (assoc type $stacks)))))
	 (progn
	 `(declare (ignore $push $pop))
	 ,@body)
	 $stacks))))




(defun %$call-op (op)
  (let ((peek-args (mapcar #'$peek (op-sig op))))
    (unless (some #'null peek-args)
      (let ((args (mapcar (lambda (x)
			    (if (member (car (op-ret op)) '(:list))
				($pop-keep-types x)
				($pop x)))
			  
			  (op-sig op))))
	(format t "********** calling ~A ************~%" (op-name op))
	(format t ">> args: ~S~%" args)
	(if (eq (op-ret op) :unpack-list)
	    (mapcar #'$push (apply (op-func op) args))
	    (mapcar
	     (lambda (x y)
	       ($push (cons x y)))
	     (op-ret op)
	     (apply (op-func op) args)))))))
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
	     `(progn
		(defparameter ,(intern (format nil "!~A-~A" type suffix))
		  (make-operation
		   :name (quote ,(intern (format nil "!~A-~A" type suffix)))
		   :sig (quote ,(loop for i below param-arity collect type))
		   :ret (quote ,(loop for i below ret-arity collect type))
		   :func (lambda ,arglist
			   (progn
			     ,@body))))
		(push ,(intern (format nil "!~A-~A" type suffix))
		      *operations*)))))

(defmacro def-move-op (dest)
  (cons 'progn
	(loop for type in (remove-if (lambda (x) (eq x dest))
				     *stack-types*)
	   collect
	     `(progn
		(defparameter ,(intern (format nil "!~A->~A" type dest))
		  (make-operation
		   :name (quote ,(intern (format nil "!~A->~A" type dest)))
		   :sig (quote ,(list type))
		   :ret (quote ,(list dest))
		   :func #'list))
		(push ,(intern (format nil "!~A->~A" type dest))
		      *operations*)))))


(export 'run)
(defun run (exec-stack)
  (with-stacks #.*stack-types*
    ($clear)
    ($load-exec exec-stack)
    (loop while (cdr (assoc :exec $stacks)) do
	 ($exec ($pop :exec)))))


;; To make a random individual exec-stack:

;; list of basic constants should be supplied with the first element
;; being a type keyword, and the rest being values of that type --
;; the same structure used in the stacks, essentially.

(export 'random-stack)
(defun random-stack (typed-stacks
		     &key
		       (operations *operations*)
		       (seed #xdead533d)
		       (typed-minlens)
		       (total-maxlen))
  (unless (assoc :op typed-stacks)
    (push (cons :op operations) typed-stacks))
  (let* ((typed-minlens (copy-seq typed-minlens))
	 (*std-prng* (mersenne:make-mt seed))
	 (types (mapcar #'car typed-stacks))
	 (stack ()))
    (labels ((pick-type ()
	       (elt types (mersenne:std-rndnum (length types))))
	     (type-count (type)
	       (when (numberp (cadr (assoc type typed-minlens)))
		 (decf (cadr (assoc type typed-minlens)))))
	     (min-crit ()
	       (every (lambda (x) (or (null x)
				      (<= x 0)))
		      (mapcar #'cadr typed-minlens)))
	     (max-crit ()
	       (or (null total-maxlen)
		   (>= (length stack) total-maxlen))))
      (loop while (not (and (min-crit) (max-crit))) do
	   (let* ((typ (pick-type))
		  (stk (cdr (assoc typ typed-stacks))))
	     (type-count typ)
	     (push (cons typ (elt stk (std-rndnum (length stk))))
		   stack)))
      stack)))
	     
	   
      
    
(defun print-exec-stack (es)
  (mapc (lambda (x)
	  (format t "* ~A~%" (repr x))) es)
  nil)
