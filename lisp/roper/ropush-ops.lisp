(in-package :ropush)
;; SPECIAL OPS
(defop !!halt
    :sig ()
    :ret ()
    :func (lambda ()
	    (setq $halt t)))

;; GENERIC OPS
(def-generic-op rot+
    :sig (* * *)
    :ret (* * *)
    :encaps nil
    :func (lambda (x y z)
	    (list z x y)))

(def-generic-op rot-
    :sig (* * *)
    :ret (* * *)
    :encaps nil
    :func (lambda (x y z)
	    (list y z x)))

(def-generic-op swap
    :sig (* *)
    :ret (* *)
    :encaps nil
    :func (lambda (x y)
	    (list y x)))

(def-generic-op dup
    :sig (*)
    :ret (* *)
    :encaps nil
    :func (lambda (x)
	    (list x x)))

(def-generic-op over
    :sig (* *)
    :ret (* * *)
    :encaps nil
    :func (lambda (a b)
	    (list )))

;; STANDARD OPS
(defop !int->dword
    :sig (:int)
    :ret (:dword)
    :func (lambda (x)
	    (ldb (byte 32 0) x)))

(defop !pointer->dword
    :sig (:pointer)
    :ret (:dword)
    :func #'list)

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

(defop !list-len
    :sig (:list)
    :ret (:int)
    :func (lambda (x) (length x)))

(defop !string-len
    :sig (:string)
    :ret (:int)
    :func (lambda (x) (length x)))

(defop !store-code
    :sig (:exec)
    :ret (:code)
    :func #'list)

(defop !load-code
    :sig (:code)
    :ret (:exec)
    :func #'list)

(defun 2list (x y)
  (list y x))

(defop !int->list
    :sig (:int :int)
    :ret (:list)
    :func #'2list)

(defop !list->ints
    :sig (:list)
    :ret () ;; OVERRIDE
    :func (mk-unpacker :int))


(defop !gadget->list
    :sig (:gadget :gadget)
    :ret (:list)
    :func #'2list)

(defop !pointer->list
    :sig (:pointer :pointer)
    :ret (:list)
    :func #'2list)


(defop !exec->list
    :sig (:exec :exec)
    :ret (:list)
    :func #'2list)

(defop !list-merge
    :sig (:list :list)
    :ret (:list)
    :func (lambda (x y)
	    (append y x)))

(defop !list-reverse
    :sig (:list)
    :ret (:list)
    :func (lambda (x)
	    (reverse x)))

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
