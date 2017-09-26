(in-package :ropush)

(defun safemod (number divisor)
  (if (zerop divisor) 0
      (mod number divisor)))

;; SPECIAL OPS
(defop !!halt
    :sig ()
    :ret ()
    :func (lambda ()
	    (setq $halt t)))

;; GENERIC OPS
(defop rot+
    :sig (? ? ?)
    :ret (? ? ?)
    :strip nil
    :encaps nil
    :func (lambda (x y z)
	    (list z x y)))

(defop pair
    :sig (? ?)
    :ret (:list ?)
    :strip nil
    :encaps t
    :func (lambda (x y)
	    `(:list ,x ,y)))

(defop rot-
    :sig (? ? ?)
    :ret (? ? ?)
    :encaps nil
    :strip nil
    :func (lambda (x y z)
	    (list y z x)))

(defop swap
    :sig (? ?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (x y)
	    (list y x)))

(defop dup
    :sig (?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (x)
	    (list x x)))

(defop over
    :sig (? ?)
    :ret (? ? ?)
    :encaps nil
    :strip nil
    :func (lambda (a b)
	    (list b a b)))

(defop drop
    :sig (?)
    :ret ()
    :func (lambda (x)))

(defop reload
    :sig (?)
    :ret (:code)
    :encaps t
    :strip t
    :func (lambda (x)
	    (cons (car sig) x)))

(defop ==
    :sig (? ?)
    :ret (:bool)
    :func (lambda (x y)
	    (equalp x y)))

(defop flush
    :sig (?)
    :ret ()
    :func (lambda (_)
	    (declare (ignore _))
	    (setf ($stack-of (car sig)) ())))

;(defop yank
;    :sig (:int ?)
;    :ret (?);; add point display to mode-line construct
;    :peek t ;; to prevent indexing errors
;    :func (lambda (i _)
;	    (let ((stk))
;	      (declare (ignorable _))
;	      (setq stk ($stack-of (car ret)))
;	      (if (null stk)
;		  _
;		  (excise stk (safemod i (length stk)))))))

(defop shove 
    :sig (:int ?)
    :ret ()
    :peek t
    :func (lambda (i thing)
	    (let ((stk))
	      ;; lisp doesn't like me putting car or sig in the let decl
	      (setq stk ($stack-of (cadr sig)))
	      (insert stk
		      (safemod i (length stk))
		      ;; consing together with type info, again,
		      ;; since the return action is nonstandard
		      (cons (cadr sig) thing)))))

(defop stackdepth
    :sig (?)
    :ret (:int)
    :peek t
    :encaps t
    :func (lambda (_)
	    (declare (ignore _))
	    ($depth (car sig))))

;;; combinators ;;;

(defop S
    :sig (? ? ?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (a b c)
	    (declare (ignore a))
	    (list 
	     `(:list ,b ,c)
	     c)))

(defop K
    :sig (? ? ?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (a b c)
	    (declare (ignore b))
	    (list a c)))

;; byte ops

;; Packs a byte to a series of integers, with the proper endian
(defop !bytes->ints
    :sig (:bytes)
    :ret (:list :int) ;; of ints
    :func (lambda (s) (bytes->dwords s :endian <endian>)))
	  ;  (mapcar (lambda (x)
;		      (cons :int x))

(defop !bytes-len
    :sig (:bytes)
    :ret (:int)
    :func #'length)

(defop !bytes-drop
    :sig (:bytes :int)
    :ret (:bytes)
    :func (lambda (s i)
	    (subseq s (min i (length s)))))

(defop !bytes-take
    :sig (:bytes :int)
    :ret (:bytes)
    :func (lambda (s i)
	    (subseq s 0 (min i (length s)))))

(defop !ratio->int
    :sig (:ratio)
    :ret (:int)
    :func (lambda (x)
	    (denominator x)))

(defop !int->ratio
    :sig (:int)
    :ret (:ratio)
    :func (lambda (x)
	    (/ 1 (min 1 (abs x)))))

(defop !ratio-plus
    :sig (:ratio :ratio)
    :ret (:ratio)
    :func (lambda (x y)
	    (min 1 (+ x y))))

(defop !ratio-mult
    :sig (:ratio :ratio)
    :ret (:ratio)
    :func (lambda (x y)
	    (max *min-ratio* (* x y))))





;;; Boolean operators

(defun true (x) (/= x 0))
(defun false (x) (= x 0))
(defun bool (x) (if x 1 0))

(defop !bool-or
    :sig (:bool :bool)
    :ret (:bool)
    :func (lambda (x y)
	    (or (true x)
		(true y))))

(defop !bool-and
    :sig (:bool :bool)
    :ret (:bool)
    :func (lambda (x y)
	    (and (true x) (true y))))

(defop !bool-xor
    :sig (:bool :bool)
    :ret (:bool)
    :func (lambda (x y)
	    (and (or (true x) (true y))
		 (or (false x) (false y)))))


;;; Conditionals

(defop !code-if-else
    :sig (:bool :code :code)
    :ret (:code)
    :func (lambda (i th el)
	    (if (true i) th el)))

;;; integer operators


(defop !int-plus
    :sig (:int :int)
    :ret (:int)
    :func #'+)

(defop !int-minus
    :sig (:int :int)
    :ret (:int)
    :func #'-)

(defop !int-mult
    :sig (:int :int)
    :ret (:int)
    :func #'*)

(defop !int-div
    :sig (:int :int)
    :ret (:int)
    :func (lambda (x y)
	    (if (zerop y)
		x
		(round (/ x y)))))

(defop !int-mod
    :sig (:int :int)
    :ret (:int)
    :func (lambda (x y)
	    (if (zerop y)
		x
		(mod x y))))

(defop !int-<
    :sig (:int :int)
    :ret (:bool)
    :func (compose #'bool #'<))

(defop !int->
    :sig (:int :int)
    :ret (:bool)
    :func (compose #'bool #'>))

(defop !int-<=
    :sig (:int :int)
    :ret (:bool)
    :func (compose #'bool #'<=))

(defop !int->=
    :sig (:int :int)
    :ret (:bool)
    :func (compose #'bool #'>=))

(defop !int-and
    :sig (:int :int)
    :ret (:int)
    :func #'logand)

(defop !int-xor
    :sig (:int :int)
    :ret (:int)
    :func #'logxor)

(defop !int-flip
    :sig (:int)
    :ret (:int)
    :func (lambda (x)
	    (ldb (byte 32 0) (lognot x))))

(defop !int->bytes
    :sig (:int)
    :ret (:bytes)
    :func #'dword->bytes)

(defop !bytes-concat
    :sig (:bytes :bytes)
    :ret (:bytes)
    :func (lambda (a b) (concatenate 'bytes a b)))

(defop !bytes-aref
    :sig (:bytes :int)
    :ret (:int)
    :func (lambda (b i)
	    (aref b i)))


;;; Womb and Germ
(defop >womb 
    :sig (?)
    :ret (:womb)
    :strip nil
    :cast t
    :encaps t
    :func #'identity);(lambda (x)
	  ;  (cons (car sig) x)))

(defop !pop-womb
    :sig (:womb)
    :ret (:code)
    :strip t
    :cast t
    :encaps t
    :func #'identity)

;; think about how to implement loops.
