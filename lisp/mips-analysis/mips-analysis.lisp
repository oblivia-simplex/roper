(in-package :mips-analysis)

(defun opcode (w)
  (ldb (byte 6 26) w))

;; simpler than ARM. we just look at the opcode, so we don't need
;; an elaborate masking schema.
(defparameter +i-opcodes+
  '((#b001000 :addi);
    (#b001001 :addiu);
    (#b001100 :andi);
    (#b000100 :beq);
    (#b000001 :bgez);rt = 00001
    (#b000111 :bgtz);rt = 00000
    (#b000110 :blez);rt = 00000
    (#b000001 :bltz);rt = 00000
    (#b000101 :bne);
    (#b100000 :lb);
    (#b100100 :lbu);
    (#b100001 :lh);
    (#b100101 :lhu);
    (#b001111 :lui);
    (#b100011 :lw);
    (#b110001 :lwc1);
    (#b001101 :ori);
    (#b101000 :sb);
    (#b001010 :slti);
    (#b001011 :sltiu);
    (#b101001 :sh);
    (#b101011 :sw);
    (#b111001 :swc1);
    (#b001110 :xori)));

(defparameter +func-codes+
  '((#b100000 :add) ;; rd, rs, rt
    (#b100001 :addu) ;; rd, rs, rt
    (#b100100 :and) ;; rd, rs, rt
    (#b001101 :break) ;; 
    (#b011010 :div) ;; rs, rt
    (#b011011 :divu) ;; rs, rt
    (#b001001 :jalr) ;; rd, rs
    (#b001000 :jr) ;; rs
    (#b010000 :mfhi) ;; rd
    (#b010010 :mflo) ;; rd
    (#b010001 :mthi) ;; rs
    (#b010011 :mtlo) ;; rs
    (#b011000 :mult) ;; rs, rt
    (#b011001 :multu) ;; rs, rt
    (#b100111 :nor) ;; rd, rs, rt
    (#b100101 :or) ;; rd, rs, rt
    (#b000000 :sll) ;; rd, rt, sa
    (#b000100 :sllv) ;; rd, rt, rs
    (#b101010 :slt) ;; rd, rs, rt
    (#b101011 :sltu) ;; rd, rs, rt
    (#b000011 :sra) ;; rd, rt, sa
    (#b000111 :srav) ;; rd, rt, rs
    (#b000010 :srl) ;; rd, rt, sa
    (#b000110 :srlv) ;; rd, rt, rs
    (#b100010 :sub) ;; rd, rs, rt
    (#b100011 :subu) ;; rd, rs, rt
    (#b001100 :syscall) ;; 
    (#b100110 :xor))) ;; rd, rs, rt

(defparameter +func-map+
  (let ((m (make-array (expt 2 6) :initial-element nil)))
    (loop for (fc mnem) in +func-codes+ do
      (setf (aref m fc) mnem))
    m))

(defparameter +j-opcodes+
  '((#x02 :j)
    (#x03 :jal)))

(defparameter +layouts+
  (let ((m (make-array (expt 2 6) :initial-element nil)))
    (setf (aref m 0) :Lay=R)
    (loop for (op _) in +i-opcodes+
          do (setf (aref m op) :Lay=I))
    (loop for (op _) in +j-opcodes+
          do (setf (aref m op) :Lay=J))
    m))

(defun what-layout (w)
  (aref +layouts+ (opcode w)))

(defun funccode (w)
  (ldb (byte 6 0) w))

(defun get-func (w)
  (when (eq (what-layout w) :Lay=R)
    (aref +func-map+ (funccode w))))

(defun rs (w)
  (ldb (byte 5 21) w))

(export '+inst-size+)
(defvar +inst-size+ 4)

(export 'jump-reg)
(defun jump-reg (w)
  (when (eq (get-func w) :jr)
    (rs w)))

(export 'retp)
(defun retp (_)
  nil)
