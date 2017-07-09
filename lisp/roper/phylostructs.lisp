;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Data structures for phylogenic process (Representation) ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(in-package :phylostructs)

(defvar +word-size+ 32)
(defvar +max-clump-size+ 32)

(deftype word () '(unsigned-byte 32))
(deftype maybe-float () '(or null double-float))
(deftype maybe-bytes () '(or null (cons (unsigned-byte 8))))
(deftype maybe-words () '(or null (cons word)))
(deftype word-list () '(or null (cons word)))

(export '(make-clump
	  clump
	  cl-sp-delta
	  cl-ret-offset
	  cl-ret-addr
	  cl-words
	  cl-mode
	  cl-visc
	  cl-link-age
	  cl-link-fit))
(defstruct (clump
            (:conc-name cl-)
            (:constructor make-clump))
  (sp-delta 0 :type integer)
  (ret-offset 0 :type integer)
  (ret-addr 0 :type integer)
  (words nil :type word-list)
  (mode :arm :type keyword)
  (visc 50 :type integer)
  (link-age 0 :type integer)
  (link-fit nil :type maybe-float))

(deftype clump-list () '(or null (cons clump)))


(export '(chain
	  make-chain
	  ch-clumps
	  ch-packed
	  ch-relfit
	  ch-absfit
	  ch-parfit
	  ch-gen
	  ch-verbose
	  ch-crashes
	  ch-season))
(defstruct (chain
            (:conc-name ch-))
  (clumps () :type clump-list)
  (packed nil :type maybe-bytes)
  (relfit nil :type maybe-float)
  (absfit nil :type maybe-float)
  (parfit nil :type maybe-float)
  (gen 0 :type integer)
  (verbose nil :type boolean)
  (crashes nil :type boolean)
  (season 0 :type integer))

(deftype chain-list () '(or null (cons clump)))

(defun hexdump (byte-vec)
  (with-output-to-string (s)
    (loop for b across byte-vec
          for i from 1 do
            (format s "~2,'0X " b)
            (when (zerop (mod i 16))
              (terpri s)))))

(defun clump-row (clump)
  (with-output-to-string (s)
    (loop for w in (cl-words clump) do
      (format s "~8,'0X " w))
    (terpri s)))

(defparameter *hrule*
  "==============================================================")

(defun show-chain (chain)
  (format nil "~A
Relative Fitness: ~F [Season: ~D]
Absolute Fitness: ~F
Parental Fitness: ~F
Generation:       ~D
Link ages:   ~S
Link fits:   ~S
Viscosities: ~S
Clumps:~%~A
Packed:~%~A
~A~%"
          *hrule*
          (ch-relfit chain) (ch-season chain)
          (ch-absfit chain)
          (ch-parfit chain)
          (ch-gen chain)
          (mapcar #'cl-link-age (ch-clumps chain))
          (mapcar #'cl-link-fit (ch-clumps chain))
          (mapcar #'cl-visc (ch-clumps chain))
          (apply #'concatenate 'string
                 (mapcar #'clump-row (ch-clumps chain)))
          (when (ch-packed chain)
            (hexdump (ch-packed chain)))
          *hrule*))


(defun saturated-p (clump)
  (= (length (cl-words clump))
     (cl-sp-delta clump)))

(defun splice-at-offset (dest offset src)
  (loop for item in src
        for i from offset do
        (setf (aref dest i) item)))

(defun conc-clumps (clumps)
  (let* ((s (reduce #'+ (mapcar (lambda (x) (length (cl-words x)))
                                clumps)))
         (rto 0)
         (words (make-array s :element-type 'word)))
    (loop for clump in clumps do
      (assert (saturated-p clump))
      (assert (<= 0 (cl-sp-delta clump)))
      (splice-at-offset words rto (cl-words clump))
      (when (eq (cl-mode clump) :THUMB)
        (incf (aref words rto))) ;; thumb addrs have 1 at LSB
      (incf rto (cl-ret-offset clump)))
    words))



(export 'saturate-clump)
(defun saturate-clump (clump constant-dispenser)
  (let ((sat (copy-structure clump))
	(words (list (car (cl-words clump)))))
    (loop repeat (1- (cl-sp-delta clump)) do
	 (push (funcall constant-dispenser) words))
    (setf (cl-words sat) (nreverse words)) 
    sat))

(export 'make-random-dispenser)
(defun make-random-dispenser (constants seed)
  (let ((constants (make-array (length constants)
			       :initial-contents constants))
	(len (length constants))
	(rng (mersenne:make-mt seed)))
    (lambda ()
      (aref constants (mod (mersenne:mt-gen rng) len)))))

;; TODO:
;; * saturate-gadgets with constants
;; * create initial populations
;; * rewrite tournament and fitness sharing functions,
;   borrowing from GENLIN and rust implementation of ROPER

;; (export '(chain
;; 	  ch-clumps
;; 	  ch-packed
;; 	  ch-rel-fit
;; 	  ch-par-fit
;; 	  ch-generation
;; 	  ch-season
;; 	  ch-crashes))
;; (defstruct chain
;;   (clumps () :type (or null (cons clump)))
;;   (packed () :type (or null (cons (unsigned-byte 8))))
;;   (rel-fit nil :type (or null float))
;;   (abs-fit nil :type (or null float))
;;   (par-fit nil :type (or null float))
;;   (generation 0 :type fixnum)
;;   (season 0 :type fixnum)
;;  (crashes nil :type boolean))

(export 'saturated-p)
(defun saturated-p (clump)
  (= (cl-sp-delta clump) (length (cl-words clump))))

(export 'tesselate-cl-words)
(defun tesselate-cl-words (clumps)
  (let ((words ()))
    (loop for clump in clumps do
	 (let ((upto (- (cl-sp-delta clump)
			(cl-ret-offset clump))))
	   (format t "upto: ~D~%" upto)
	   (assert (< 0 upto))
	   (loop for i below upto do
		(push (elt (cl-words clump) i) words))))
    (reverse words)))

(export 'pack-chain)
(defun pack-chain (chain &key (endian :little))
  (let ((words (tesselate-cl-words (ch-clumps chain))))
    (format t "words: ~S~%" words)
    (setf (ch-packed chain)
	  (dwords->bytes words :endian endian))))


(export 'make-chains)
(defun make-chains (clumps &key constants number seed min-size max-size endian)
  (let* ((rng (mersenne:make-mt seed))
	 (constant-dispenser (make-random-dispenser constants seed))
	 (sats (mapcar (lambda (x) (saturate-clump x constant-dispenser))
		       clumps))
	 (cl-dispenser (make-random-dispenser sats seed))
	 (population ()))
    (loop repeat number do
	 (let* ((len (+ (mod (mersenne:mt-gen rng)
			     (- max-size min-size))
			min-size))
		(chain (make-chain
			:clumps (loop repeat len
				   collect (funcall cl-dispenser)))))
	   (pack-chain chain :endian endian)
	   (push chain population)))
    population))


(export 'clump-ret)
(defun clump-ret (clump)
  (elt (cl-words clump)
       (cl-ret-offset clump)))

(export 'chain-rets)
(defun chain-rets (chain)
  (mapcar #'clump-ret (ch-clumps chain)))

(export 'init-population)
(defun init-population (&key section
			  constants
			  (number 100)
			  (seed 42)
			  (min-size 1)
			  (max-size 16)
			  (arch 2ndvariety::*arch*)
			  (endian :little))
  (make-population :deme (make-chains (2ndvariety::find-gadgets section :arch arch)
				      :constants constants
				      :number number
				      :seed seed
				      :min-size min-size
				      :max-size max-size
				      :endian endian)))


(export '(population
	  make-population
	  pop-deme
	  pop-best
	  pop-iter
	  pop-season
	  pop-params))
(defstruct (population (:conc-name pop-))
  (deme nil :type (or null (cons chain)))
  (best nil :type (or null chain))
  (iter 0 :type integer)
  (season 0 :type integer)
  (params () :type list))
