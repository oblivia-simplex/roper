(in-package :ropush)
(use-package :phylostructs)
(use-package :unicorn)
(use-package :hatchery)


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
    :gas 2
    :func (lambda ()
	    ($emu nil ;; halt
		  1   ;; num
		  )))

(defop !!emu-all
    :sig ()
    :ret ()
    :gas (* *gadget-emu-cost* ($depth :gadget))
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

;;; Some operations that seek data from the unicorn ;;;

(defop !emu-mem-read
    :sig (:int :int)
    :ret (:bytes)
    :func (lambda (addr size)
	    (uc-mem-read (emu-engine $unicorn) addr size)))

(defop !emu-mem-read-int
    :sig (:int)
    :ret (:int)
    :func (lambda (addr)
	    (bytes->dword (uc-mem-read (emu-engine $unicorn) addr 4)
			  :offset 0
			  :endian <endian>)))

;; ** > Add two untyped stacks, X and Y.
;; these can be used as scratch space in runs
;; and will be preloaded with the two parents in sexual reproduction
;; * Autoconstruction:
;; Load untyped stacks with parents
;; Load :womb code into :code
;; run :womb code
;; child is whatever is left in :womb at the end.
;; -- we can just use :womb for either x or y.
;; -- so we just need one more additional stack.

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

(defun $emu (halt num)
  ;; may need to optimize this later
  ;; NOP if $unicorn unset
  (when $unicorn
    (let* ((payload (push-stacks->payload $stacks num))
					;(packed (dwords->bytes payload
					;			:endian <endian>))
	   (out (if halt :output! :int)))
      (when payload
	(multiple-value-bind (registers errorcode pc)
	    (hatchery:hatch-chain :emu $unicorn
				  :payload payload
				  ;; it'd be nice to set input and output regs from here
				  :input (cdr (assoc :input! $stacks))) ;; ADJUSTABLE
	  ;; now put these back on the stack
	  ;; handle output
	  ;; when halt flag is set, send 
	  ($push (cons out pc))
	  ($push (cons out (unicorn:errorcode->int errorcode)))
	  (mapcar (lambda (x)
		    ($push (cons out x)))
		  registers))
	(when halt (setq $halt t))
	nil))))


(defparameter *spare-constant* 1)
(defun push-stacks->payload (stacks &optional num)
  "Generates an attack payload from the state of the stacks."
  (let ((gadgets (cdr (assoc :gadget stacks)))
	(dispense (make-cyclical-dispenser
		   (mapcar (lambda (n) (ldb (byte <word-size> 0) n))
			   (cons *spare-constant*
				 (cdr (assoc :int stacks))))))
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

