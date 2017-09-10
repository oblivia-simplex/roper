;: PushGP variant for ROPER
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
  (peek nil :type bool)
  (fetch)
  (func #'identity))

(defun mangle-symbols (syms)
  (let ((i 0)
	(mangs ()))
    (loop for sym in syms do
	 (push (intern (format nil "_~A_~D" sym i)) mangs)
	 (incf i))
    mangs))

;; deprecated -- using #'compose from junk-drawer now
;(defmacro encaps-fn (sig fn)
;  "Takes a function and a signature list, then returns a new function
;that returns the value of the old function, wrapped in a list"
;  (let ((mang (mangle-symbols sig)))
;    `(lambda ,mang
;       (list (apply ,fn `(,,@mang))))))

(defun %mk-arg-fetch (sig ret peek)
  (let ((topf (if peek
		  #'$peek
		  (if (member (car ret) '(:list))
		      #'$pop-keep-types
		      #'$pop))))
    (lambda ()
      (nreverse (mapcar topf sig)))))

(defmacro defop (name &key sig ret func peek (encaps t))
  (let ((fn (if encaps
		`(compose #'list ,func)
		func)))
    `(progn
       (defparameter ,name (make-operation
			    :name (quote ,name)
			    :sig (quote ,(reverse sig))
			    :ret (quote ,ret)
			    :fetch (%mk-arg-fetch (quote ,sig)
						  (quote ,ret)
						  (quote ,peek))
			    :func ,fn))
       (push ,name *operations*)
       ,name)))

(defmacro def-unpacker-op (type)
  (let ((name (intern (format nil "!LIST->~A" type))))
    `(defop ,name
	 :sig (:list)
	 :ret ()
	 :peek nil
	 :func (mk-unpacker ,type))))

;; Some standard functions

(defmacro def-generic-op (suffix &key sig ret peek encaps func)
  ;; new syntax
  (labels ((wildcard (type s)
	     (mapcar (lambda (x) (if (eq x '*) type x)) s)))
    (cons 'progn
	  (loop for type in *stack-types*
	     collect
	       (let ((name (intern (format nil "!~A-~A" type suffix))))
		 `(defop ,name
		      :sig ,(wildcard type sig)
		      :ret ,(wildcard type ret)
		      :peek ,peek
		      :encaps ,encaps
		      :func ,func))))))

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
			       )))
       (incf $counter)
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

;; supply input as special stack, which can only be accessed by $emu
(defmacro with-stacks (stack-keywords unicorn &rest body)
  ;; the unicorn parameter can be either nil, or point to a unicorn
  ;; engine, to be used in evaluating certain gadget expressions
  `(let (($counter 0)
	 ($halt nil)
	 ($unicorn ,unicorn)
	 ($stacks
	  (quote ,(loop for key in stack-keywords
		    collect
			`(,key . ())))))
     (declare (ignorable $halt
			 $unicorn))
     (labels (($stackf (key)
		(cdr (assoc key $stacks)))
	      ;; bit of a hack here: this "setf" works like a push.
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


  
;; i don't like the keep-types hack... but i don't see a way around it yet
(defun %$call-op (op)
  (let ((peek-args (mapcar #'$peek (op-sig op))))
    (unless (some #'null peek-args)
      (let ((args (funcall op-fetch)))
;;	(format t "********** calling ~A ************~%" (op-name op))
;;	(format t ">> args: ~S~%" args)
	;; abandoned this unpack-list type, i think.
	;(if (eq (op-ret op) :unpack-list)
	 ;   (mapcar #'$push (apply (op-func op) args))
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


(defparameter *halt-hooks* '())

(export 'run)
(defun run (exec-stack &key (max-push-steps <max-push-steps>)
			 (unicorn nil))
  (with-stacks #.*stack-types* unicorn
    ($clear)
    (print 'hi)
    ($load-exec exec-stack)
    (loop while (and (not $halt)
		     (cdr (assoc :exec $stacks))
		     (< $counter max-push-steps))
       do
	 ($exec ($pop :exec)))
    (loop for hook in *halt-hooks* do
	 ($exec hook))))



;;;;;;;;;;;;; put the following in its own file. it
;; has to do with individual generation, and not with the
;; ropush logic itself

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


