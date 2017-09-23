(in-package :ropush)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;                        Test Functions                      ;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defparameter code-stack-1
  (list 
	`(:int . 1000)
	(cons :bytes #(1 2 3 4 5 6 7 8 9 10 11 12))
	`(:op . ,!bytes->ints)
	`(:int . 1)
	`(:op . ,!int-<)
	`(:op . ,!code-if-else)
	`(:op . ,!int-dup)
	`(:op . ,!code-dup)
	`(:op . ,!int-over)
	`(:op . ,!code->womb)
	`(:op . ,!int-rot+)
	`(:op . ,!code->womb)
	`(:op . ,!bytes-dup)
	`(:op . ,!bytes-len)))


(defparameter code-stack-2
  (list (cons :int 3)
	(cons :int 4)
	(cons :op !int-dup)
	(cons :op !int-mult)
	(cons :op !int-dup)
	(list :list (cons :int 5) (cons :op !int-plus))
	(cons :op !exec-s)
	(cons :op !int-pair)
	(cons :op !int->womb)
	(cons :op !int-reload)
	(cons :op !pop-womb)
	(cons :op !int-dup)
	(cons :op !int-rot+)))

(defparameter code-stack-3
  (list (cons :int 10)
	(cons :gadget (make-gadget :SP-DELTA 6 :RET-OFFSET 3 :RET-ADDR #x16110 :ENTRY #x16108))
	(cons :gadget (make-gadget :SP-DELTA 4 :RET-OFFSET 0 :RET-ADDR #x161BC :ENTRY #x161B0))
	(cons :op !!emu-1)
	(cons :op !gadget-dup)
	(cons :op !int-plus)))

