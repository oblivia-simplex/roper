;: PushGP variant for ROPER
;; individual isn't a ROP chain, but a ROP chain builder

(in-package :ropush)


(defparameter *operations* '())

(defstruct (operation (:conc-name op-))
  (name 'unnamed-operation :type symbol)
  (sig () :type (or null (cons keyword)))
  (sigcard () :type (or null (cons (cons keyword fixnum))))
  (ret () :type (or null (cons keyword)))
  (peek nil :type boolean)
  (gas 1) ;; ripping off ethereum here.
  (fetch)
  (func #'identity))

(defun mk-sigcard (siglist)
  (let ((sigcard ()))
    (loop for s in (reverse siglist) do
	 (if (assoc s sigcard)
	     (incf (cdr (assoc s sigcard)))
	     (push (cons s 1) sigcard)))
    sigcard))

(defun mangle-symbols (syms)
  (let ((i 0)
	(mangs ()))
    (loop for sym in syms do
	 (push (intern (format nil "_~A_~D" sym i)) mangs)
	 (incf i))
    mangs))

;; Some standard functions
(defvar ?)

;; refactor, maybe
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


(defun $push (typ.val)
  (funcall $$push typ.val))

(defun $peek (typ)
  (funcall $$peek typ))

(defun $pop (typ)
  (funcall $$pop typ))

(defun $depth (typ)
  (funcall $$depth typ))

(defun $stack-of (typ)
  (funcall $$stack-of typ))

(defun (setf $stack-of) (lst typ)
       (setf (cdr (assoc typ $stacks)) lst))

(defun $clear ()
  (mapcar (lambda (x) (setf (cdr x) nil)) $stacks))

;;;;;
;; better, homogeneous treatment: lists are just operations
;; that return their own bodies.
;;;;;;;;
(defun $exec (item)
  #+debugging
  (format t "~A~%[~D]---[ executing ~A~%[~D]---[ stacks before:~%~A~%"
	  (concatenate 'string (loop repeat 78 collect #\-))
	  $counter (repr item) $counter (repr-stack-tops $stacks))
  (cond ((eq (car item) :op)
	 (decf $counter (op-gas (cdr item)))
	 (mapcar (lambda (x) ($push (cons :exec x)))
		 ($call-op (cdr item))))
	((eq (car item) :list)
	 (decf $counter)
	 (mapcar #'$exec (cdr item)))
	(t (decf $counter)
	   (when (member (car item) $types)
	     ($push item))))
  #+debugging
  (format t "[~D]---[ stacks after:~%~A~%" $counter (repr-stack-tops $stacks)))

(defmacro with-stacks (stack-keywords unicorn gas &rest body)
  ;; the unicorn parameter can be either nil, or point to a unicorn
  ;; engine, to be used in evaluating certain gadget expressions
  `(let* ((_sk (if (listp ,stack-keywords)
		  ,stack-keywords
		  (symbol-value ,stack-keywords)))
	 (_stacks (mapcar (lambda (k) (cons k ())) _sk)))
    (let* (($stacks `(,@_stacks))
	   ($types (mapcar #'car $stacks))
	   ($counter ,gas)
	   ($halt nil)
	   ($unicorn ,unicorn)
	   ($$push
	    (lambda (type.val)
	      (push (cdr type.val)
		    (cdr (assoc (car type.val) $stacks)))))
	    ($$depth
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
	   `(declare (ignorable $unicorn $counter
				$$depth $$push $$pop $$peek))
	   ,@body)
	 $stacks)))


(defun %spy-args (op)
  ;; check to see if sufficient args are on the stacks
  (block spy
    (loop for (type . card) in (op-sigcard op) do
       ;; i don't like that this evaluates the entire length of the stack
	
	 (when (or (not (member type $types))
		   (< ($depth type) card))
	   (return-from spy nil)))
    t))

(defun $call-op (op)
  ;; NOP if not enough arguments on the stacks
  (when (%spy-args op)
    (let ((args (funcall (op-fetch op))))
      (apply (op-func op) args))))

(defun $load-code (code-stack)
  ;(print-stack code-stack)
  (setf (cdr (assoc :code $stacks)) code-stack))

(defun $load-stack (stack type)
  (setf (cdr (assoc type $stacks)) stack))

(defparameter *halt-hooks* '())

(defun $step ()
  (funcall $$push (cons :exec (cdr (funcall $$pop :code))))
  (loop while (cdr ($peek :exec)) do
       ($exec (cdr ($pop :exec)))))

(export 'run)
(defun run (code-stack &key (unicorn nil)
			 (gas <gas-limit>)
			 (stack-types *stack-types*)
			 (halt-hooks *halt-hooks*))
  (with-stacks stack-types
    unicorn gas
    ($load-stack code-stack :code)
    (loop while (and (not $halt)
		     (cdr (assoc :code $stacks))
		     (> $counter 0))
       do
	 ($step))
    (mapc #'$exec halt-hooks)))


;; this is where the type-stripping should happen,
;; since it's easy to configure from the op.
(defun %mk-arg-fetch (sig peek strip)
  (let* ((%topf (if peek #'$peek #'$pop))
	 (topf (if strip
		   (compose #'cdr %topf)
		   %topf)))
    (lambda ()
      (mapcar topf sig))))

(defmacro defop% (name &key
			sig
			ret
			func
			peek
			(cast)
			(strip t)
			(gas 1)
			(encaps t))
  (let* ((type-pre (if (and (or strip cast) ret)
		       (if (and (eq (car ret) :list)
				(cdr ret))
			   '(lambda (lst)
			     (cons :list
			      (mapcar (lambda (y) (cons (cadr ret) y)) lst)))
			   '(lambda (x) (cons (car ret) x)))
		       '#'identity))
	 (encaps-pre (if (and encaps ret)
			 '#'list
			 '#'identity))
	 (fn `(compose ,encaps-pre ,type-pre ,func)))
    `(prog1
       (defparameter ,name (make-operation
			    :name (quote ,name)
			    :sig (quote ,sig)
			    :sigcard (quote ,(mk-sigcard sig))
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

(defmacro defop (op-name &key sig
			   ret
			   peek
			   func
			   (gas 1)
			   (types *stack-types*)
			   (exclude-types `(:!output!))
			   (encaps t)
			   (strip t)
			   (cast))
  (cons 'progn
	(loop for __type in
	     (if (member '? (append sig ret))
		 (remove-if (lambda (x) (member x exclude-types))
			    types)
		 '(*)
		 )
	   collect
	     (let ((name (if (char= #\! (aref (symbol-name op-name) 0))
			     op-name
			     (intern (format nil "!~A-~A"
					     __type op-name))))
		   (? __type))
	       `(defop% ,name
		    :sig ,(mapcar #'symbol-value sig)
		    :ret ,(mapcar #'symbol-value ret)
		    :peek ,peek
		    :encaps ,encaps
		    :strip ,strip
		    :cast ,cast
		    :gas ,gas
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
  (let* ((typed-minlens (mapcar #'copy-seq typed-minlens))
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
      (print typed-minlens)
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


