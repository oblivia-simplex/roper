;; ropush breeding algorithms


(defun mate (parents unicorn &optional (gas <gas-limit>))
  (let ((germs (apply #'append
		      (mapcar (lambda (p)
				(mapcar (lambda (c)
					  (cons :womb c))
					(cr-code p)))
		       parents))))
    (let ((stacks (run (append germs (cr-code (car parents)))
		       :unicorn unicorn
		       :gas gas)))
      ;; add a diversity check. apply crossover or mutation if failed
      (assoc :womb stacks))))

(defun validate-children (parents children)
  )

(defun crossover (parents)
  )


