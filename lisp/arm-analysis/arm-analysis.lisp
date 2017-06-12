(in-package :arm-analysis)

(defvar +masks+
  '((#b00001111111111111111111111010000
     #b00000001001011111111111100010000
     :Lay=BX)  ;; Found a bug in the spec document?
    (#b00001111110000000000000011110000
     #b00000000000000000000000010010000
     :Lay=MULT)
    (#b00001111100000000000000011110000
     #b00000000100000000000000010010000
     :Lay=MULT_L)
    (#b00001100000000000000000000000000
     #b00000000000000000000000000000000
     :Lay=DP)
    (#b00001111101100000000111111110000
     #b00000001000000000000000010010000
     :Lay=SDS)
    (#b00001110010000000000111110010000
     #b00000000000000000000000010010000
     :Lay=HDT_R)
    (#b00001110010000000000000010010000
     #b00000000010000000000000010010000
     :Lay=HDT_I)
    (#b00001100000000000000000000000000
     #b00000100000000000000000000000000
     :Lay=SDT)
    (#b00001110000000000000000000010000
     #b00000110000000000000000000010000
     :Lay=UNDEF)
    (#b00001110000000000000000000000000
     #b00001000000000000000000000000000
     :Lay=BDT)
    (#b00001110000000000000000000000000
     #b00001010000000000000000000000000
     :Lay=BR)
    (#b00001110000000000000000000000000
     #b00001100000000000000000000000000
     :Lay=CDT)
    (#b00001111000000000000000000010000
     #b00001110000000000000000000000000
     :Lay=CDO)
    (#b00001111000000000000000000010000
     #b00001110000000000000000000010000
     :Lay=CRT)
    (#b00001111000000000000000000000000
     #b00001111000000000000000000000000
     :Lay=SWI)))

(defun what-layout (w)
  (loop for (mask sig lay) in +masks+ do
    (when (= (logand mask w) sig)
      (return lay))))


(defun range (lo hi)
  (loop for i from lo to (1- hi) collect i))

(defun bdt-rlist (w)
  (remove-if-not (lambda (i) (< 0 (logand (ash 1 i) w)))
                 (range 0 16)))

(defun dp-opcode (w)
  (ldb (byte 4 21) w))

(defun dp-immediate (w)
  (= (ldb (byte 1 25) w) 1))

;;;;;;;;;;;;;;;;;;;;;;;
;; Generic Interface
;;;;;;;;;;;;;;;;;;;;;;;

(export 'jumpp)
(defun jumpp (w)
  (member (what-layout w)
	  '(:Lay=BX :Lay=BR)))

(export 'syscallp)
(defun syscallp (w)
  (eq (what-layout w) :Lay=SWI))

(export 'jump-reg)
(defun jump-reg (w)
  (let ((layout (what-layout w)))
    (cond ((eq layout :Lay=BX)
           (ldb (byte 4 0) w))
          ((and (eq layout :Lay=DP)
                (= (ldb (byte 1 25) w) 0) ;; immediate flag
                (= (arith-dst-reg w) +pc+)
                (= (dp-opcode w) #b1101) ;; MOV
                (= (ldb (byte 8 4) w) 0)) ;; no shift. simplification
           (ldb (byte 4 0) w)))))

(export 'pop-regs)
(defun pop-regs (w)
  (when (and (eq (what-layout w) :Lay=BDT)
             (= (bdt-stack-dir w) +pop-dir+))
    (bdt-rlist w)))

(export 'push-regs)
(defun push-regs (w)
  (when (and (eq (what-layout w) :Lay=BDT)
             (= (bdt-stack-dir w) +push-dir+))
    (bdt-rlist w)))

(export 'foo)
(defun foo (w)
  (format t "hello from foo! ~S~%" w))

(export 'retp)
(defun retp (w)
  (when w
    (and (eq (what-layout w) :Lay=BDT)
	 (eq (ldb (byte 4 16) w) +sp+)
         (< 0 (logand (ash 1 +pc+) w)))))

;(defun stack-delta-rlist (w)
;  (if (eq (what-layout w) :Lay=BDT)
;      (let ((rlist (bdt-rlist w)))
;        (list (* (bdt-stack-dir w) (length rlist)) rlist))
;      (list 0 nil)))

(junk-drawer:def-bitcounter 16)
(defun stack-delta (w)
  (if (and (eq (what-layout w) :Lay=BDT)
	   (eq (ldb (byte 4 16) w) +sp+) ;; is a push/pop
	   (eq (ldb (byte 1 21) w) 1)) ;; writeback
      (* (bdt-stack-dir w)
         (bitcounter-16 w))
      0))

(export 'pop-offset)
(defun pop-offset (w r)
  (position r (reverse (pop-regs w)) :test #'=))

(export 'arith-dst-reg)
(defun arith-dst-regs (w)
  (when (eq (what-layout w) :Lay=DP)
    (list (ldb (byte 4 12) w))))

(export 'arith-src-regs)
(defun arith-src-regs (w)
  (when (eq (what-layout w) :Lay=DP)
    (let ((lst (list (ldb (byte 4 16) w))))
      (when (not (dp-immediate w))
	(push (ldb (byte 4 0) w) lst)))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;






(defvar +sp+ 13)
(defvar +lr+ 14)
(defvar +pc+ 15)

(defvar +special-registers+ (list +sp+ +lr+ +pc+))

(defun bdt-first-reg (w)
  (ldb (byte 4 16) w))

(defun read-bit (w i)
  (ldb (byte 1 i) w))

(defvar +pop-dir+ +1)
(defvar +push-dir+ -1)
 ;       ((zerop (read-bit w 21)) 0)


(defun bdt-stack-dir (w)
  (if (zerop (read-bit w 23))
      +push-dir+
      +pop-dir+))


(defun tally-arith-reg (insts)
  (let ((arith-insts (remove-if-not
                   (lambda (w) (eq (what-layout w) :Lay=DP))
                   insts))
        (src-tally (make-list 16 :initial-element 0))
        (dst-tally (make-list 16 :initial-element 0)))
    (loop for inst in arith-insts do
      (incf (elt src-tally (car (arith-src-regs inst))))
      (incf (elt src-tally (cadr (arith-src-regs inst))))
      (incf (elt dst-tally (arith-dst-reg inst))))
    (list (list :src src-tally)
          (list :dst dst-tally))))

(defun partial (f &rest args1)
  (lambda (&rest args2)
    (apply f (append args1 args2))))

;(defun tally-pop-regs (insts &key (rets-only t))
;  (apply #'mapcar #'+
;         (append '((0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))


(defun word->bits (w &key (width 32) (offset 0))
  (loop for i from offset to (1- width) collect
        (ldb (byte 1 i) w)))

(defun tally-pop-regs (insts &key (mode :arm) (rets-only t))
  (apply #'mapcar #'+
         (append (list (word->bits 0 :width 16))
                 (mapcar #'word->bits
                         (remove-if-not
                          (lambda (w)
                            (if rets-only
                                (retp w)
                                (eq (what-layout w) :Lay=BDT)))
                          insts)))))

(defun get-pop-rlists (insts &key (rets-only t))
  (mapcar #'bdt-rlist
          (remove-if-not
           (lambda (w)
             (if rets-only (retp w)
                 (eq (what-layout w) :Lay=BDT)))
           insts)))


(defun extract-by-name (elf-obj name)
  "Returns a named section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (let* ((secs (elf:sections elf-obj))
         (addrs (mapcar #'elf:address (elf:section-table elf-obj)))
         (named-idx (position name secs
                              :key #'elf:name :test #'equalp)))
    (values (elf:data (elt secs named-idx))
            (elt addrs named-idx))))



(defun inst-words-from-file (path &key (width 4))
  (let* ((elf (elf:read-elf path))
         (text (extract-by-name elf ".text")))
    (get-words text)))



;;;;;;;;;;;;;;;;;;;;;;
;; CSV generation
;;;;;;;;;;;;;;;;;;;;;;;;

;; refactor this, and separate analytics from IO
(defun register-profile (path)
  (let* ((insts (inst-words-from-file path))
         (pops (list :pops (tally-pop-regs insts :rets-only nil)))
         (rets (list :rets (tally-pop-regs insts :rets-only t)))
         (dp (tally-arith-reg insts))
         (srcs (assoc :src dp))
         (dsts (assoc :dst dp)))
    (list pops rets srcs dsts)))




(defun profile-crossrows (prof)
  (let ((hdr (mapcar #'car prof))
        (body (mapcar #'cadr prof)))
    (cons hdr
          (loop for i in (range 0 16)
                collect (mapcar (lambda (x) (elt x i)) body)))))

(defun logscale-crossrows (xprof)
  (cons (car xprof)
        (mapcar (lambda (x)
                  (mapcar (lambda (y) (if (zerop y) y (log y 2))) x))
                (cdr xprof))))

(defun reg-prof-csv (path &key (out) (logscale))
  (let* ((prof (register-profile path))
         (xprof (profile-crossrows prof))
         (csv (mapcar #'list->csv
                      (if logscale
                          (logscale-crossrows xprof)
                          xprof))))
    (if (not out) csv
        (with-open-file (stream out :direction :output)
          (loop for row in csv
                for i from -1 to 15 do
            (format stream "~A,~A~%" (if (< i 0) 'REG i) row))))))


