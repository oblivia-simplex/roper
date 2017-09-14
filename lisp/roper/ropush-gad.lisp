(in-package :ropush)
(use-package :phylostructs)


(defmacro def-gadget-inspector (field-symbol &rest return-types)
  (let ((name (intern (format nil "!GADGET-~A" field-symbol)))
	(accessor-symbol (intern (format nil "GAD-~A" field-symbol))))
    `(progn
       (defparameter ,name (make-operation
			    :sig '(:gadget)
			    :ret (quote ,return-types) 
			    :func
			    (lambda (x)
			      (list
			       (funcall ,(symbol-function accessor-symbol) x)))))
       (push ,name *operations*))))

;; SPECIAL OPS

(defparameter *gadget-emu-cost* 2)

(defop !!emu-1
    :sig ()
    :ret ()
    :gas (*gadget-emu-cost*)
    :func (lambda ()
	    ($emu nil ;; halt
		  1   ;; num
		  )))

(defop !!emu-all
    :sig ()
    :ret ()
    :gas (* *gadget-emu-cost* ($height :gadget))
    :func (lambda ()
	    ($emu nil nil)))

(defop !!emu-halt
    :sig ()
    :ret ()
    :func (lambda ()
	    ($emu t nil)))

(push (cons :op !!emu-halt) *halt-hooks*)

;; STANDARD OPS

(defop !gadget-sp-delta
    :sig (:gadget)
    :ret (:int)
    :peek t
    :func #'gad-sp-delta)

(defop !gadget-ret-addr
    :sig (:gadget)
    :ret (:int)
    :peek t
    :func #'gad-ret-addr)

(defop !gadget-ret-offset
    :sig (:gadget)
    :ret (:int)
    :peek t
    :func #'gad-ret-offset)

(defop !gadget-entry
    :sig (:gadget)
    :ret (:int)
    :peek t
    :func #'gad-entry)

(defop !gadget-discard
    :sig (:gadget)
    :ret ())

;; Experiment plan:
;; * try varying the visibility of the input vector
;;   to the push programs. What happens when the
;;   only influence the input can have on the program
;;   is in terms of fitness?
;;   How does this differ than what we see where the
;;   push code itself can respond dynamically to different
;;   input vectors?
;;   What if the input vector is visible only to $emu?
;;   What if it can be manipulated like the other stacks?

(defstackfn $emu (halt num)
  ;; may need to optimize this later
  ;; NOP if $unicorn unset
  (when $unicorn
    (let* ((payload (push-stacks->payload $stacks num))
					;(packed (dwords->bytes payload
					;			:endian <endian>))
	   (out (if halt :output! :int)))
      (multiple-value-bind (registers errorcode pc)
	  (hatchery:hatch-chain :emu $unicorn
				:payload payload
				;; it'd be nice to set input and output regs from here
				:input (funcall $stackf :input!)) ;; ADJUSTABLE
	;; now put these back on the stack
	;; handle output
	;; when halt flag is set, send 
	($push (cons out pc))
	 ($push (cons out errorcode))
	 (mapcar (lambda (x)
		   ($push (cons out x)))
		 registers))
      (when halt (setq $halt t)))))
  
(defun push-stacks->payload (stacks &optional num)
  "Generates an attack payload from the state of the stacks."
  (let ((gadgets (cdr (assoc :gadget stacks)))
	(dispense (make-cyclical-dispenser
		   (mapcar (lambda (n) (ldb (byte <word-size> 0) n))
			   (cdr (assoc :int stacks)))))
	(payload ()))
    (if (and num (< num (length gadgets)))
	(setq gadgets (subseq gadgets 0 num)))
    ;; copying code from phylostructs:tesselate-cl-words [deprecated]
    (loop for gadget in gadgets do
	 (let ((upto (- (gad-sp-delta gadget)
			(gad-ret-offset gadget))))
	   (assert (< 0 upto))
	   (push (gad-entry gadget) payload)
	   ;; double check for off-by-one errors here.
	   (loop for i below (1- upto) do
		(push (funcall dispense) payload))))
    (reverse payload)))

