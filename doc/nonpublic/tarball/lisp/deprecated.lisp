;; don't want to throw these bits out yet, but I'm not using them
;; in the current version

;; this bit here is from rosetta code

(defvar *sigint*   2)
(defvar *sigsegv* 11)

;; deprecated
(defmacro set-signal-handler (signo &body body)
  (let ((handler (gensym "handler")))
    `(progn
      (cffi:defcallback ,handler :void ((signo :int))
        (declare (ignore signo))
        ,@body)
      (cffi:foreign-funcall "signal" :int ,signo :pointer
                            (cffi:callback ,handler)))))


(defcstruct (user_regs_struct :size 216);;(get-size-of-registers))
  ;; Copied essentially verbatim from sys/user.h 
  (r15 :long) (r14 :long) (r13 :long) (r12 :long)
  (rbp :long) (rbx :long) (r11 :long) (r10 :long)
  (r9 :long)  (r8 :long)  (rax :long) (rcx :long)
  (rdx :long) (rsi :long) (rdi :long) (orig_rax :long)
  (rip :long) (cs :long)  (eflags :long)   (rsp :long)
  (ss :long) (fs_base :long) (gs_base :long) (ds :long)
  (es :long) (fs :long) (gs :long))


(defmacro get-size-of-registers ()
  (foreign-funcall "size_of_registers" :int))

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



;; deprecated
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



(defun socket-read-bytes (socket &key (timeout 10))
  (let ((stream (usocket:socket-stream socket)))
    (usocket:wait-for-input (list socket) :timeout timeout)
    (loop while (listen stream) collect (read-byte stream))))

(defun socket-send-bytes (socket bytes)
   (loop for byte in bytes do (write-byte byte (usocket:socket-stream socket)))
   (force-output (usocket:socket-stream socket)))


(defun ready-socket (&key (ip #(127 0 0 1)) (port *code-server-port*)
                       (timeout 10))
       (usocket:socket-connect
                 ip port
                 :element-type '(unsigned-byte 8) :timeout timeout))


;; this version of dispatch works with the usocket library.
;; i'm currently preferring the iolib version, above. 
(defun u-dispatch (code &key (ip #(127 0 0 1))
                        (port *code-server-port*)
                        (header #x00))
  "The header is one byte long. The lower nibble should be set to 0
for virtualized execution (using Unicorn), or 1 for bare metal
execution. If virtualized execution is chosen, then the upper nibble
is consulted. Set it to 1 for ARM, or 0 for x86_64."
  (let ((socket (usocket:socket-connect
                 ip port
                 :element-type '(unsigned-byte 8))))
    (socket-send-bytes socket (cons header code))
     (let ((result (bytes->sexp (socket-read-bytes socket))))
      (usocket:socket-close socket)
      result)))

