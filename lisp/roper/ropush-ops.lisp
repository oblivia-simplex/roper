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
(def-generic-op rot+
    :sig (? ? ?)
    :ret (? ? ?)
    :strip nil
    :encaps nil
    :func (lambda (x y z)
	    (list z x y)))


(def-generic-op rot-
    :sig (? ? ?)
    :ret (? ? ?)
    :encaps nil
    :strip nil
    :func (lambda (x y z)
	    (list y z x)))

(def-generic-op swap
    :sig (? ?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (x y)
	    (list y x)))

(def-generic-op dup
    :sig (?)
    :ret (? ?)
    :encaps nil
    :strip nil
    :func (lambda (x)
	    (list x x)))

(def-generic-op over
    :sig (? ?)
    :ret (? ? ?)
    :encaps nil
    :strip nil
    :func (lambda (a b)
	    (list b a b)))

(def-generic-op drop
    :sig (?)
    :ret ()
    :func (lambda (x)))

(def-generic-op reload
    :sig (?)
    :ret (:code)
    :func (lambda (x)
	    (cons (car sig) x))) ;; anaphoric reference

(def-generic-op ==
    :sig (? ?)
    :ret (:bool)
    :func (lambda (x y)
	    (equalp x y)))

(def-generic-op flush
    :sig (?)
    :ret ()
    :func (lambda (_)
	    (declare (ignore _))
	    (setf ($stack-of (car sig)) ())))

(def-generic-op yank
    :sig (:int)
    :ret (?);; add point display to mode-line construct
    :peek t ;; to prevent indexing errors
    :func (lambda (i)
	    (let ((stk))
	      (setq stk ($stack-of (car ret)))
	      (excise stk (safemod i (length stk))))))

(def-generic-op shove 
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

(def-generic-op height
    :sig (?)
    :ret (:int)
    :peek t
    :encaps t
    :func (lambda (_)
	    (declare (ignore _))
	    ($height (car sig))))

(defop !int-plus
    :sig (:int :int)
    :ret (:int)
    :func (lambda (x y)
	    (+ x y)))

(defop !int-string-plus
    :sig (:int :int)
    :ret (:string)
    :func (lambda (x y)
	    (format nil "The answer is ~D" (+ x y))))


(defop !string-len
    :sig (:string)
    :ret (:int)
    :func #'length)

(defop !store-womb
    :sig (:int)
    :ret (:womb)
    :func #'identity)

(defop !load-womb
    :sig (:womb)
    :ret (:code)
    :func #'identity)

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

(defop !int-mult
    :sig (:int :int)
    :ret (:int)
    :func (lambda (x y)
	    (* x y)))


;;; Exec combinators ;;;

(defop !code-S
    :sig (:code :code :code)
    :ret (:code :code)
    :encaps nil
    :strip nil
    :func (lambda (a b c)
	    (declare (ignore a))
	    (list 
	     `(:list ,b ,c)
	     c)))

(defop !exec-S
    :sig (:exec :exec :exec)
    :ret (:exec :exec)
    :encaps nil
    :strip nil
    :func (lambda (a b c)
	    (list 
	     `(:list ,b ,c)
	     c
	     a)))

