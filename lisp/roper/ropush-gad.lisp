(in-package :ropush)
(use-package :phylostructs)


(defmacro def-gadget-inspector (field-symbol &rest return-types)
  (let ((name (intern (format nil "!GADGET-~A" field-symbol)))
	(accessor-symbol (intern (format nil "CL-~A" field-symbol))))
    `(progn
       (defparameter ,name (make-operation
			    :sig '(:gadget)
			    :ret (quote ,return-types) ;; (quote (,return-types))
			    :func
			    (lambda (x)
			      (list
			       (funcall ,(symbol-function accessor-symbol) x)))))
       (push ,name *operations*))))


(def-gadget-inspector sp-delta :int)
(def-gadget-inspector ret-addr :dword)
(def-gadget-inspector ret-offset :int)
(def-gadget-inspector link-age :int)
(def-gadget-inspector visc :ratio)
(def-gadget-inspector activation-threshold :ratio)
(def-gadget-inspector activation-influence :ratio)


(defop !gadget-entry
    :sig (:gadget)
    :ret (:dword)
    :func (lambda (x)
	    (list (car (cl-words x)))))


(defop !gadget-visc-inc
    :sig (:gadget)
    :ret (:gadget)
    :func (lambda (x)
	    (let ((g (copy-clump g)))
	      (setf (cl-visc g)
		    (min (* 5/4 (cl-visc g)) 1/1))
	      g)))

(defop !gadget-visc-dec
    :sig (:gadget)
    :ret (:gadget)
    :func (lambda (x)
	    (let ((g (copy-clump g)))
	      (setf (cl-visc g)
		    (* 3/4 (cl-visc g)))
	      g)))

(defop !gadget-activ-inf-inc
    :sig (:gadget)
    :ret (:gadget)
    :func (lambda (x)
	    (let ((g (copy-clump g)))
	      (setf (cl-activation-influence g)
		    (min (* 5/4 (cl-activation-influence g)) 1/1))
	      g)))

(defop !gadget-activ-inf-dec
    :sig (:gadget)
    :ret (:gadget)
    :func (lambda (x)
	    (let ((g (copy-clump g)))
	      (setf (cl-activation-influence g)
		    (* 3/4 (cl-activation-influence g)))
	      g)))

(defop !gadget-clump-dword
    :sig (:gadget :dword)
    :ret (:gadget)
    :func (lambda (g d)
	    (let ((g (copy-clump g)))
	      (push d (cl-words g)))))

