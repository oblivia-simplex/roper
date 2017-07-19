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
(def-gadget-inspector visc :int)

(defop !gadget-entry
    :sig (:gadget)
    :ret (:dword)
    :func (lambda (x)
	    (list (car (cl-words x)))))


