;: PushGP variant for ROPER
;; individual isn't a ROP chain, but a ROP chain builder

(in-package :ropush)

(defparameter *operations* '())

(defstruct (operation (:conc-name op-))
  (name 'unnamed-operation :type symbol)
  (sig () :type (or null (cons keyword)))
  (ret () :type (or null (cons keyword)))
  (peek nil :type boolean)
  (gas 1) ;; ripping off ethereum here.
  (fetch)
  (func #'identity))

(defun mangle-symbols (syms)
  (let ((i 0)
	(mangs ()))
    (loop for sym in syms do
	 (push (intern (format nil "_~A_~D" sym i)) mangs)
	 (incf i))
    mangs))




;; Some standard functions
(defvar ?)

(defun repr (unit)
  (when unit
    (let ((val-str 
	   (cond ((operation-p unit) (format nil "~A " (op-name unit)))
		 ((listp unit) (case (car unit)
				 ((:op) (format nil "(:OP . ~A) " (op-name (cdr unit))))
				 ((:list) (format nil "[ ~A ] "
						  (apply #'concatenate 'string (mapcar #'repr (cdr unit)))))
				 (otherwise (format nil "~S " unit))))
		 (t (format nil "~S " unit)))))
      val-str)))


(defparameter *longest-stack-name-length*
  (reduce #'max (mapcar (compose #'length #'symbol-name) *stack-types*)))

(defun repr-stack-tops (stacks)
  (let ((fstr (make-array '(0) :element-type 'base-char
			  :fill-pointer 0
			  :adjustable t)))
    (with-output-to-string (s fstr)
      (loop for stack in stacks do
	   ;(format s "  ~A: ~A [top of ~D]~%" (car stack) (repr (cadr stack)) (length (cdr stack)))))
	   (format s "~A:~A ~A~A~%"
		   (car stack)
		   (coerce (loop repeat
				(- *longest-stack-name-length*
				   (length (symbol-name (car stack))))
			      collect #\Space)
			   'string)
		   #\Space
		   (apply #'concatenate 'string (mapcar #'repr (cdr stack))))))
    fstr))

(defun abridge-to-str (lst &optional (maxlen 10))
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
       ,(if (and *debug* (eq name '$call-op)) `(progn
		       (format t "[~D] ~A ~A -> ~A~%~A~%"
			       $counter
			       (quote ,name)
			       (apply #'concatenate 'string (mapcar #'repr (list ,@arglist)))
			       (if (listp __res)
				   (repr __res) ;(apply #'concatenate 'string (mapcar #'repr __res))
				   (repr __res))
			       (repr-stack-tops $stacks)
			       )))
       __res)))


(defstackfn $push (typ.val)
  (funcall $$push typ.val))

(defun $peek (typ)
  (funcall $$peek typ))

(defstackfn $pop (typ)
  ;; this might help
  (funcall $$pop typ))
;(if (eq typ :code);
		    ; :exec
		    ; typ)))

(defstackfn $height (typ)
  (funcall $$height typ))

(defun $stack-of (typ)
  (funcall $$stack-of typ))

(defun (setf $stack-of) (lst typ)
       (setf (cdr (assoc typ $stacks)) lst))
#+ropush-list-support
(defstackfn $pop-keep-types (typ)
  (funcall $$pop typ :keep-types t))

(defun $clear ()
  (mapcar (lambda (x) (setf (cdr x) nil)) $stacks))

;;;;;
;; better, homogeneous treatment: lists are just operations
;; that return their own bodies.
;;;;;;;;
(defun $exec (item)
  (format t "~%---[ executing ~S~%---[ stacks before:~%~S~%" item $stacks) 
  (cond ((eq (car item) :op)
	 ;(format t "$EXEC> ~A~%" (repr item))
	 (incf $counter (op-gas (cdr item)))
	 ;(let ((res ($call-op (cdr item))))
	 ;  (when res (mapcar (lambda (x) ($push (cons :exec x))) res))))
	 (mapcar (lambda (x) ($push (cons :exec x)))
		 ($call-op (cdr item))))
	((eq (car item) :list)
	 ;(format t "$EXEC> ~A~%" (repr item))
	 (incf $counter)
	 (mapcar #'$exec (cdr item)))
	(t ;(format t "$EXEC> ~A~%" (repr item))
	   (incf $counter)
	   ($push item)))
  (format t "--[ stacks after:~%~S~%" $stacks))

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
       (let (($$push
	      (lambda (type.val)
		(push (cdr type.val)
		      (cdr (assoc (car type.val) $stacks)))))
	     ($$height
	      (lambda (type)
		(length (cdr (assoc type $stacks)))))
	     ($$pop
	      (lambda (type)
		(cons type 
		      (pop (cdr (assoc type $stacks))))))
	     ($$peek
	      (lambda (type)
	        (cons type
		      (cadr (assoc type $stacks)))))
	     ($$stack-of
	      (lambda (type)
		(cdr (assoc type $stacks)))))
	 (progn
	 `(declare (ignorable $$height $$push $$pop $$peek))
	 ,@body)
	 $stacks)))


  
(defun %$call-op (op)
  (let ((peek-args (mapcar #'$peek (op-sig op))))
    (unless (some #'null peek-args)
      (let ((args (funcall (op-fetch op))))
;	(mapcar
	; #'$push
	 (apply (op-func op) args)))))

(defstackfn $call-op (op)
  (%$call-op op))

(defun $load-code (code-stack)
  (print-stack code-stack)
  (setf (cdr (assoc :code $stacks)) code-stack))


;; a unit will be either a type.val pair, or an op.
;(defstruct unit
;  (kind nil :type (or null keyword))
					;  (body


(defparameter *halt-hooks* '())

(defun $step ()
  (funcall $$push (cons :exec (cdr (funcall $$pop :code))))
  (loop while (cdr ($peek :exec)) do
       ($exec (cdr ($pop :exec)))))
  
(export 'run)
(defun run (code-stack &key (max-push-steps <max-push-steps>)
			 (unicorn nil))
  (with-stacks #.*stack-types* unicorn
    ($clear)
    ($load-code code-stack)
    (loop while (and (not $halt)
		     (cdr (assoc :code $stacks))
		     (< $counter max-push-steps))
       do
	 ($step))
    (loop for hook in *halt-hooks* do
	 ($exec hook))))

;; THIS is where the type-stripping should happen,
;; since it's easy to configure from the op. 
(defun %mk-arg-fetch (sig peek strip)
  (let* ((%topf (if peek #'$peek #'$pop))
	 (topf (if strip
		   (compose #'cdr %topf)
		   %topf)))
    (lambda ()
      (nreverse (mapcar topf sig)))))

(defmacro defop (name &key
			sig
			ret
			func
			peek
			(strip t) 
			(gas 1)
			(encaps t))
  (let* (;(strip (if (not encaps) 
;		    nil
;		    strip))
	 (type-pre (if (and strip ret)
		       '(lambda (x) (cons (car ret) x))
		       '#'identity))
	 (encaps-pre (if (and encaps ret)
			 '#'list
			 '#'identity))
	 (fn `(compose ,encaps-pre ,type-pre ,func)))
    `(prog1
       (defparameter ,name (make-operation
			    :name (quote ,name)
			    :sig (quote ,(reverse sig))
			    :ret (quote ,ret)
			    :gas (quote ,gas)
			    :fetch (%mk-arg-fetch (quote ,sig)
						  (quote ,peek)
						  (quote ,strip))
			    :func (let ((sig ',sig)
					(ret ',ret))
				    (declare (ignorable sig ret))
				    ,fn)))
       (push ,name *operations*))))

(defun mk-unpacker (type)
  (lambda (lst)
    (mapcar #'$push
	    (remove-if-not (lambda (y) (eq (car y) type))
			   lst))))

;(defmacro def-unpacker-op (type)
;  (let ((name (intern (format nil "!LIST->~A" type))))
;    `(defop ,name
	 ;; :sig (:list)
	 ;; :ret ()
	 ;; :peek nil
	 ;; :encaps nil
;;	 :func (mk-unpacker ,type))))

(defmacro def-generic-op (suffix &key sig ret peek encaps func (strip t))
  ;; new syntax
  ;(labels ((wildcard (type s)
;	     (mapcar (lambda (x) (if (eq x '*) type x)) s)))
    (cons 'progn
	  (loop for __type in *stack-types*
	     collect
	       (let ((name (intern (format nil "!~A-~A" __type suffix)))
		     (? __type))
		 `(defop ,name
		      :sig ,(mapcar #'symbol-value sig)
		      :ret ,(mapcar #'symbol-value ret)
		      :peek ,peek
		      :encaps ,encaps
		      :strip ,strip
		      :func ,func)))))

;;;;;;;;;;;;; put the following in its own file. it
;; has to do with individual generation, and not with the
;; ropush logic itself

;; To make a random individual code-stack:

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
	     
	   
      
    
(defun print-stack (es)
  (mapc (lambda (x)
	  (format t "* ~A~%" (repr x))) es)
  nil)


