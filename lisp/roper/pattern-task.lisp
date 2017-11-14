
;;;;;;;;
;; The pattern matching fitness function
;;;;;;


;; first, we need to be able to parse the pattern language.

;; S := (E*)
;; E := int | string | wildcard | &E

;; & is the indirection operator.

(defun int->reg (int)
  )


(defun parse-indirection (sym)
  (let ((str (symbol-name sym))
	(deg 0)
	(num)
	(*read-base* #x10))
    (loop for i below (length str) do
	 (if (char= (aref str i) #\&)
	     (incf deg)
	     (progn
	       (setq num (read-from-string (subseq str i)))
	       (return))))
    (assert (numberp num))
    (list deg num)))

(defun deref (ptr deg uc)
  (let ((errcode))
    (format t ">> ptr = ~A~%" ptr)
    (loop repeat deg
       while ptr do
	 (multiple-value-bind (bytes err)
	     (uc-mem-read uc ptr 4)
	   (setq errcode err)
	   (unless bytes
	     (setq ptr nil)
	     (return))
	   (setq ptr (bytes->dword (uc-mem-read uc ptr 4))) ;; NB: word size dependent
	   (format t ">> ptr = ~A~%" ptr)))
    (values ptr errcode)))


(defun check-elem (elem reg)
  (cond ((number elem)
	 (lambda (uc)
	   (- (uc-reg-read uc reg
			   :arch <cpu-arch>)
	      elem))
	 ((symbolp elem)
	  (if (eq elem #\_)
	      (lambda (_)) ;; nop
	      (lambda (uc)
		(check-deref elem reg uc))))
	 
	 
	
