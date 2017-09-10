(in-package #:2ndvariety)


(export '*word-size*)
(defparameter *word-size* 4)

(export '*arch*)
(defparameter *arch* :ARM)

;(defstruct clump
;  (words () :type (or null (cons fixnum)))
;  (sp-delta 0 :type fixnum)
;  (ret-offset 0 :type fixnum)
;  (ret-addr 0 :type fixnum)
;  (viscosity 50 :type fixnum)
;  (input-slots)
;  (mode)
;  (link-age 0 :type fixnum)
;  (link-fit nil :type (or null float)))

(defmacro defdispatch (name arglist)
  (let ((fn (gensym "FN")))
    `(defun ,name (,@arglist &key (arch *arch*))
       (let ((,fn
	      (intern (format nil "~A" ',name)
		      (intern (format nil "~A-ANALYSIS" arch)))))
	 (funcall (symbol-function ,fn) ,@arglist)))))

(defdispatch retp (w))

(defdispatch jumpp (w))

(defdispatch syscallp (w))

(defdispatch jump-reg (w))

(defdispatch pop-regs (w))

(defdispatch push-regs (w))

(defdispatch arith-src-regs (w))

(defdispatch arith-dst-regs (w))

(defdispatch stack-delta (w))

(defdispatch pop-offset (w r))



(defun is-ret (addr sec &key (arch *arch*))
  (let ((w (word-at sec addr)))
    (when w
      (retp w :arch arch))))

(defun is-jump (addr sec)
  (let ((w (word-at sec addr)))
    (when w
      (numberp (jump-reg w)))))

(defun is-ctrl (addr sec &key (arch *arch*))
  (let ((w (word-at sec addr)))
    (when w
      (or (retp w :arch arch)
	  (jumpp w :arch arch)))))

(defun sec-start (sec)
  (read-elf::sec-addr sec))

(defun sec-end (sec)
  (+ (read-elf::sec-addr sec) (length (read-elf::sec-data sec))))

(screamer::defun an-addr-in-sec (sec &key (word-size *word-size*)
                                       (low) (high))
  (let* ((m (+ (sec-addr sec)
               (- (length (sec-data sec)) word-size)))
         (lb (if low (max low (sec-addr sec)) (sec-addr sec)))
         (ub (if high (min high m) m)))
    (a-member-of
     (loop for a from lb to ub
           by word-size
           collect a))))

(defun clear-jop-interval (jumpreg jaddr paddr sec
			   &key (arch *arch*)
			     (word-size *word-size*))

  (format t "[*] CLEAR-JOP-INTERVAL: ~D over ~X -> ~X~%" jumpreg paddr jaddr)
  (if (<= (- jaddr paddr) 1)
      t
	(let ((ok t))
	  (loop
	     for @
	     from (+ paddr word-size)
	     below jaddr
	     by word-size
	     while ok
	     do
	       (let ((w (word-at sec @)))
		 (format t "INSPECTING ~X~T@ ~X~T~%" w @)
		 (setq ok
		       (not (or (retp w)
				(/= (stack-delta w :arch arch) 0)
				(member jumpreg
					(arith-dst-regs w
							:arch arch))
				(jumpp w))))))
	  (format t "~A~%" (if ok "[+] OK" "[-] NOT OK"))
	  ok)))
	     



(defun find-cjumps (sec &key
			  (max-gap #x30)
			  (word-size *word-size*)
			  (arch *arch*))
  (all-values
    (let* ((p (an-addr-in-sec sec :word-size word-size))
           (j (an-addr-in-sec sec :word-size word-size
                                  :low p
                                  :high (+ p max-gap))))
      (let ((pw (word-at sec p))
            (jw (word-at sec j)))
        (assert! (andv (not (null pw)) ;; no nil-punning in screamer
                       (not (null jw))))
	(let ((jumpreg (jump-reg jw :arch arch)))
	  (assert! (and (memberv jumpreg (pop-regs pw :arch arch))
			(clear-jop-interval jumpreg j p sec)))
	  (cons p (pop-offset pw jumpreg :arch arch)))))))

;; practice
(defun find-rets (sec &key (word-size *word-size*)
			(arch *arch*))
  (all-values
    (let ((addr (an-addr-in-sec sec)))
      (assert! (zerop (mod addr word-size)))
      (assert! (is-ret addr sec :arch arch))
      (cons addr 0))))

(export 'find-gadgets)
(defun find-gadgets (sec &key (word-size *word-size*)
			   (arch *arch*))
  (let ((exits (concatenate 'list
			    (find-rets sec
				       :word-size word-size
				       :arch arch)
			    (find-cjumps sec
					 :word-size word-size
					 :arch arch))))

    (apply #'append
	   (mapcar (lambda (x) (dilate-gadget x sec))
		   exits))))

;; returns list of gadget structs
(defun dilate-gadget (addr.retoffset sec &key
					   (word-size *word-size*)
					   (arch *arch*)
					   (max-gad-len 64))
  (let* ((entries '())
	 (addr (car addr.retoffset))
	 (sp-delta (stack-delta
		    (word-at sec addr word-size) :arch arch))
	 (retoffset (cdr addr.retoffset)))
    ;; awkwardly threading ret offset data through this function
    (loop
       for a from (- addr word-size)
       downto (max (sec-addr sec) (- addr max-gad-len))
       by word-size
       while (not (is-ctrl a sec))
       do
	 (incf sp-delta (stack-delta
			 (word-at sec a word-size)
			 :arch arch))
	 (when (> sp-delta 0)
	   (push (phylostructs::make-gadget :entry a
					    :sp-delta sp-delta
					    :ret-offset retoffset
					    :ret-addr addr)
		 entries)))
    entries))

