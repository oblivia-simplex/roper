(in-package :roper-pkg)

(defparameter *debug* t)

(cffi:load-foreign-library
 #p"~/quicklisp/local-projects/roper/c/libhatchery.so")
;; may need to change this, depending on where things are.

#+sbcl
(sb-ext:unlock-package :sb-vm)

;;#+sbcl
;;(import '(sb-assem:inst sb-vm::make-ea)) 



;; "a macro for defining delimiter read-macros"
;; from paul graham's on lisp, ch. 17, fig. 17.4
(defmacro defdelim (left right parms &body body)
  `(ddfn ,left ,right #'(lambda ,parms ,@body)))

(let ((rpar (get-macro-character #\) )))
  (defun ddfn (left right fn)
    (set-macro-character right rpar)
    (set-dispatch-macro-character #\# left
                                  #'(lambda (stream char1 char2)
                                      (declare (ignorable char1 char2))
                                      (apply fn
                                             (read-delimited-list
                                              right stream t))))))

#+sbcl
(export 'sapify)
#+sbcl
(defun sapify (seq)
  (sb-sys:vector-sap
   (make-array (length seq)
               :element-type '(unsigned-byte 8)
               :initial-contents (coerce seq 'list))))

;; this might or might not come in handy...
;; #[a b c d] will be read as a system-area-pointer to bytes a b c d...
(defdelim #\[ #\] (&rest bytes)
  (sapify bytes))


;;(export 'objdump)
#+sbcl
(defun sbcl-objdump (seq &optional len)
  "reads a sequence of bytes, interprets them as machine-code
instructions, and returns their disassembly as a string. sort of like
an in-house objdump."
  (with-output-to-string (*standard-output*)
    (let ((sap (sapify seq)))
      (sb-sys:with-pinned-objects (sap)
        (sb-disassem:disassemble-memory sap (or len (length seq)))))))

(defun cffi-objdump (seq &optional len)
  (with-output-to-string (*standard-output*)
    (with-foreign-pointer (pointer (length seq) size)
      (loop for byte in seq
         for i below size do
           (setf (mem-ref pointer :unsigned-char i) byte))
      (sb-disassem:disassemble-memory pointer (or len size)))))

(export 'characters)
(defun characters (seq)
  "prints every human-readable character in the order in which it appears.
prints . for unreadable characters."
  (coerce
   (loop for byte in seq collect
        (if (and (>= byte #x20) (< byte #x7f)) (code-char byte) #\.)) 'string))

(export 'strings)
(defun strings (seq &optional (minlen 3))
  "essentially the same as the unix utility."
  (let ((strs)
        (tmp))
    (loop for byte in seq do
         (cond ((and (>= byte #x20) (< byte #x7f))
                (push (code-char byte) tmp))
               ((>= (length tmp) minlen)
                (push (coerce (reverse tmp) 'string) strs)
                (setf tmp nil))
               (:default (setf tmp nil))))
    (reverse strs)))

(export 'load-bin)
(defun load-bin (path)
  ;; this can't possibly be the best way to read in a binary file, but it works.
  (with-open-file (stream path :direction :input :element-type
                          '(unsigned-byte 8))
    (let ((bytes nil))
      (loop while (car (push (read-byte stream nil nil) bytes)))
      (reverse (cdr bytes)))))

(export 'write-bin)
(defun write-bin (bytes path)
  (with-open-file (stream path :direction :output
                          :element-type '(unsigned-byte 8))
    (loop for byte in bytes do
         (write-byte byte stream))))

(defun subupto (seq upto)
  (subseq seq 0 (min upto (length seq))))

;; note that gadgets% has almost exactly the same structure as strings
;; is there some common idiom here that we could abstract into a macro?
;; or would that just make it more complicated?
(defparameter *x86-ret* '(#xc3))
(defparameter *ret* (car *x86-ret*))

(export 'retp)
(defun retp (byte)
  (member byte *x86-ret*))

(defparameter *avoid-insts*
  '(#x5d ;; pop rbp
    ))


(defparameter *gadget-length* 32)


(export 'hexify)
(defun hexify ()
  (setq *print-base* (if (= #x10 *print-base*) #xa #x10))
  (setq *read-base* (if (= #x10 *read-base*) #xa #x10))
  (format t "setting *print-base* and *read-base* to #x~x, #x~x...~%"
          *print-base* *read-base*))
        
;; finding gadgets:
;;
;; gadgets to avoid:
;; * gadgets ending with leave, followed by ret. leave performs a pop ebp.
;; * pop ebp.
;; -- we don't want to mess up our stack frame (probably)

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; mucking around at the object level means we need to handle signals
;; when something breaks
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

;; this bit here is from rosetta code

(defvar *sigint*   2)
(defvar *sigsegv* 11)

(defmacro set-signal-handler (signo &body body)
  (let ((handler (gensym "handler")))
    `(progn
      (cffi:defcallback ,handler :void ((signo :int))
        (declare (ignore signo))
        ,@body)
      (cffi:foreign-funcall "signal" :int ,signo :pointer
                            (cffi:callback ,handler)))))

;; ----------------------------------------------------------------------



;; (defvar *initial* (get-internal-real-time))

;; (set-signal-handler *sigint*
;;   (format t "ran for ~a seconds~&" (/ (- (get-internal-real-time) *initial*)
;;                                       internal-time-units-per-second)))
  ;;  (quit))

;; (let ((i 0))
;;   (loop do
;;        (format t "~a~&" (incf i))
;;        (sleep 0.5)))






;;; --- now some more portable functions: will definitely work
;;; --- on ccl, at the very least.

;; these are going to be architecture dependent. 

(defparameter *x86_64-machine-code-prefix*
  '(#x53 #x51 #x52 #x56 #x57 #x41 #x50 #x41 #x51 #x41 #x52 #x41
    #x53 #x41 #x54 #x41 #x55 #x41 #x56 #x41 #x57 #x55 #x48 #x89 #xe5))
;; which disassembles to
;;
;; 00:       53               push rbx
;; 01:       51               push rcx
;; 02:       52               push rdx
;; 03:       56               push rsi
;; 04:       57               push rdi
;; 05:       4150             push r8
;; 07:       4151             push r9
;; 09:       4152             push r10
;; 0b:       4153             push r11
;; 0d:       4154             push r12
;; 0f:       4155             push r13
;; 11:       4156             push r14
;; 13:       4157             push r15
;; 15:       55               push rbp
;; 16:       4889e5           mov rbp, rsp


(defparameter *x86_64-machine-code-suffix*
  '(#x48 #x89 #xec #x41 #x5f #x41 #x5e #x41 #x5d #x41 #x5c #x41
    #x5b #x41 #x5a #x41 #x59 #x41 #x58 #x5f #x5e #x5a #x59 #x5b #xc3))
;; which disassembles to
;;
;; 70:       4889ec           mov rsp, rbp
;; 73:       415f             pop r15
;; 75:       415e             pop r14
;; 77:       415d             pop r13
;; 79:       415c             pop r12
;; 7b:       415b             pop r11
;; 7d:       415a             pop r10
;; 7f:       4159             pop r9
;; 81:       4158             pop r8
;; 83:       5f               pop rdi
;; 84:       5e               pop rsi
;; 85:       5a               pop rdx
;; 86:       59               pop rcx
;; 87:       5b               pop rbx
;; 88:       c3               ret


;; we still need to filter the code for a few forbidden instructions
;; "don't touch rsp, rsi, or rbp" should suffice...

(defmacro call-code (code types-and-args)
  "pokes machine code into memory and calls it as a function. 
types-and-args should be an unquoted list of the form
 :cffi-type-keyword argument :cffi-type-keyword argument [etc]
 :cffi-type-keyword
where the final type keyword specifies the return type."
  `(let ((pointer (cffi:foreign-alloc :unsigned-char
                                  :initial-contents ,code)))
    (unwind-protect 
          (cffi:foreign-funcall-pointer pointer () ,@types-and-args)
       (cffi:foreign-free pointer))))

(defun chunky-print (opseq)
  (loop for i on opseq by #'cddddr do
       (format t "~2,'0x~2,'0x~2,'0x~2,'0x~%" 
               (car i)
               (cadr i)
               (caddr i)
               (cadddr i))))


;; handy if you cut and paste in a block of machine code
;; from objdump, and want to get the instructions back in
;; order.

(defun swap-at (list i j)
            (let ((tmp (elt list i)))
              (setf (elt list i) (elt list j)
                    (elt list j) tmp)))

(defun flip-words (list)
            (loop for word on list by #'cddddr do
                 (swap-at word 0 3)
                 (swap-at word 1 2)))

(defmacro get-size-of-registers ()
  (foreign-funcall "size_of_registers" :int))

(defcstruct (user_regs_struct :size 216);;(get-size-of-registers))
  ;; Copied essentially verbatim from sys/user.h 
  (r15 :long) (r14 :long) (r13 :long) (r12 :long)
  (rbp :long) (rbx :long) (r11 :long) (r10 :long)
  (r9 :long)  (r8 :long)  (rax :long) (rcx :long)
  (rdx :long) (rsi :long) (rdi :long) (orig_rax :long)
  (rip :long) (cs :long)  (eflags :long)   (rsp :long)
  (ss :long) (fs_base :long) (gs_base :long) (ds :long)
  (es :long) (fs :long) (gs :long))



(defparameter *reg-count* 26) ;; machine dependent

(defun list->bytevec (code)
  (make-array (length code) :element-type '(unsigned-byte 8)
              :initial-contents code))


(defun size-of-sysreg-union ()
  (foreign-funcall "size_of_sysreg_union" :int))

(defun hatch-code (code &optional (seed nil))
  (let ((reg-vec (make-shareable-byte-vector (size-of-sysreg-union)))
        (seed-vec (make-shareable-byte-vector (length seed))))
    ;;(format t "reg-vec: ~A~%" reg-vec)
    (with-pointer-to-vector-data (reg-ptr reg-vec)
      (with-pointer-to-vector-data (seed-ptr seed-vec)
        (with-pointer-to-vector-data (code-ptr (list->bytevec code))
          (foreign-funcall "hatch_code"
                           :pointer code-ptr
                           :pointer seed-ptr
                           :pointer reg-ptr
                           :int)
          (loop for bytes on (coerce reg-vec 'list)
             by #'(lambda (x) (nthcdr 8 x)) collect
               (elf:bytes-to-int (subseq bytes 0 8))))))))

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; using the elf package
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(defun extract-text (elf-obj)
  "Returns the text section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (let* ((secs (elf:sections elf-obj))
         (addrs (mapcar #'elf:address (elf:section-table elf-obj)))
         (text-idx (position ".text" secs
                             :key #'elf:name :test #'equalp)))
    (values (elf:data (elt secs text-idx))
            (elt addrs text-idx))))

(defun gadmap% (bytes start &key (glength *gadget-length*))
  (let ((tyb (reverse (coerce bytes 'list)))
        (end (1- (+ start (length bytes))))
        (found 0)
        (gadmap (make-hash-table)))
    (loop for code on tyb for i from 0 do
         (when (retp (car code))
           (let* ((gad (reverse (subupto code glength)))
                 (gadlen (length gad))) ;; usually = glength
             (incf found)
             (and *debug*
                  (format t "FOUND GADGET #~:D AT 0x~X - 0x~X~%"
                          found (- end (+ i gadlen)) (- end i)))
             (setf (gethash (- end (+ i gadlen)) gadmap)
                   gad)
           (incf i glength)
           (setf code (nthcdr glength code)))))
    gadmap))
                 

(defun gadmap (elf &optional (glength *gadget-length*))
  (multiple-value-bind (text addr)
      (extract-text elf)
    (gadmap% text addr :glength glength)))
             
(defun file->gadmap (filename)
  (gadmap (elf:read-elf filename)))
   
(defun gadgets%% (elf-section &optional (gadlen *gadget-length*))
  (gadgets% (coerce (elf:data elf-section) 'list) gadlen))


(defun last3let (str) (subseq str (- (length str) 4)
                              (1- (length str))))

;; (defun shrink-gad (gadget addr)
;;   (loop while (not (string= (last3let (cffi-objdump gadget)) "RET"))
;;      do
;;        (setf gadget (cdr gadget))
;;        (incf addr))
;;   (values gadget addr))

(defun ends-with-ret-p (gadget)
  (string= (last3let (cffi-objdump gadget)) "RET"))

(defun prune-gadget (gadget &optional (addr 0))
  (loop while (or (has-bad-inst-p gadget)
                  (not (ends-with-ret-p gadget))) do
       (setf gadget (cdr gadget))
       (incf addr))
  (values gadget addr))


(defun filter-gadmap (gadmap)
  (let ((newmap (make-hash-table)))
    (loop for addr being the hash-keys in gadmap
       using (hash-value gadget) do
         (multiple-value-bind (newgadget newaddr)
             (prune-gadget gadget addr)
           (when (cdr newgadget) 
             (setf (gethash newaddr newmap) newgadget))))
    newmap))



(defun disas-inst (code)
  "Intended for disassembly of single instructions."
  (let ((dis (cffi-objdump code)))
    (chomp (subseq dis (- (length dis) 10) (length dis)))))

  
(defun chomp (str)
  (string-trim '(#\newline #\space #\linefeed #\tab) str))


;; (defun ret-filter% (gadgets)
;;   (remove-if-not #'cdr (mapcar #'shrink-gad gadgets)))


(defun has-bad-inst-p (gadget)
  ;; detects gadgets that have instructions I don't yet know how
  ;; best to deal with
  ;; first, let's catch jumps and calls
  (let ((bad '("J" "CALL" "POP" "PUSH" "SP" "IP" "["))
        (disas (cffi-objdump gadget)))
    (or (block check
          (loop for b in bad do
               (if (search b disas) (return-from check T) nil)))
        nil)))      



(defun concat-gadgets (gadget-list)
  "Concatenates gadgets, removing the *ret* instruction at the end,
first, to approximate executing them in sequence. Mostly just for
testing."
  (let ((chain))
    (loop for gadget in gadget-list do
         (setf chain (nconc chain (butlast gadget))))
    (nconc chain `(,*ret*))))



(defparameter *code-server-port* 9999)

(defun dispatch-code (code &key (ip "localhost") (port "9999"))
  (let ((code-arr (make-array (length code) ;; should already be this
                              :element-type '(unsigned-byte 8)
                              :initial-contents code)))
    (with-open-socket (socket :connect :active
                              :address-family :internet
                              :type :stream
                              :ipv6 :nil)
      (connect socket 
               (lookup-hostname ip)
               :port port :wait t)
      (send-to socket code-arr)
      (read socket))))


(defun hvals (hashmap)
  (loop for v being the hash-values in hashmap collect v))
     
;; pareto? select against bad characters, e.g.
;;;; badchars (fatal), size (bounded), accuracy (prime impt)
;; genlin
;; lisp/c
;; defences against old school stack smashing

;; numerical recipes in C

;; final paper: assume some standard conference format. IEEE, e.g.
;; look it up. submit in pdf.
;; see if there's a LaTeX pkg

