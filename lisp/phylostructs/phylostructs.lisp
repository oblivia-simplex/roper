;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Data structures for phylogenic process (Representation) ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(in-package :phylostructs)

(defvar +word-size+ 32)
(defvar +max-clump-size+ 32)

(deftype word () '(unsigned-byte 32))
(deftype maybe-float () '(or null double-float))
(deftype maybe-bytes () '(or null (simple-array (unsigned-byte 8))))
(deftype maybe-words () '(or null (simple-array word)))
(deftype word-list () '(or null (cons word)))

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
  (season 0 :type integer)
  (runtime nil :type maybe-float))

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

(defstruct (population (:conc-name pop-))
  (deme nil :type chain-list)
  (best nil :type (or null chain))
  (iter 0 :type integer)
  (season 0 :type integer)
  (params *params* :type list))
