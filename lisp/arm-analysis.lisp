(defpackage arm-analysis
  (:use :cl-user
        :elf))

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

(defun retp (w)
  (and (eq (what-layout w) :Lay=BDT)
       (< 0 (logand (ash 1 +pc+) w))))

(defun sp-delta-rlist (w)
    (if (eq (what-layout w) :Lay=BDT)
        (let ((rlist (bdt-rlist w)))
          (list (* (bdt-stack-dir w) (length rlist)) rlist))
        (list 0 nil)))

(defun sp-delta (w)
  (car (sp-delta-rlist w)))

(defvar +sp+ 13)
(defvar +lr+ 14)
(defvar +pc+ 15)

(defvar +special-registers+ (list +sp+ +lr+ +pc+))

(defun bdt-first-reg (w)
  (ldb (byte 4 16) w))

(defun read-bit (w i)
  (ldb (byte 1 i) w))

(defun bdt-stack-dir (w)
  (cond ((/= (bdt-first-reg w) +sp+) 0)
        ((zerop (read-bit w 21)) 0)
        ((zerop (read-bit w 23)) -1)
        (t +1)))

(defun dp-dst-reg (w)
  (ldb (byte 4 12) w))

(defun dp-src-reg (w)
  (ldb (byte 4 16) w))

(defun tally-dp-reg (insts)
  (let ((dp-insts (remove-if-not
                   (lambda (w) (eq (what-layout w) :Lay=DP))
                   insts))
        (src-tally (make-list 16 :initial-element 0))
        (dst-tally (make-list 16 :initial-element 0)))
    (loop for inst in dp-insts do
      (incf (elt src-tally (dp-src-reg inst)))
      (incf (elt dst-tally (dp-dst-reg inst))))
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

(defun bytes->dword (vec offset &key (width 4))
  (let ((dword 0))
    (loop for i below width do
      (incf dword
            (ash (aref vec (+ i offset)) (* i 8))))
    dword))

(defun get-words (bytes &key (width 4))
  (loop for i below (length bytes) by width collect
        (bytes->dword bytes i :width width)))

(defun extract-by-name (elf-obj name)
  "Returns a named section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (let* ((secs (elf:sections elf-obj))
         (addrs (mapcar #'elf:address (elf:section-table elf-obj)))
         (named-idx (position name secs
                              :key #'elf:name :test #'equalp)))
    (values (elf:data (elt secs named-idx))
            (elt addrs named-idx))))

(defun inst-words-from-file (path)
  (let* ((elf (elf:read-elf path))
         (text (extract-by-name elf ".text")))
    (get-words text)))

(defun register-profile (path)
  (let* ((insts (inst-words-from-file path))
         (pops (list :pops (tally-pop-regs insts :rets-only nil)))
         (rets (list :rets (tally-pop-regs insts :rets-only t)))
         (dp (tally-dp-reg insts))
         (srcs (assoc :src dp))
         (dsts (assoc :dst dp)))
    (list pops rets srcs dsts)))


(defun list->csv (l &key (fmt "~F"))
  (apply #'concatenate 'string
         (mapcar (lambda (n)
                   (format nil (concatenate 'string fmt ",") n))
                   l)))

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


        



                   
