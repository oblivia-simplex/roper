(in-package :roper-pkg)


(defun load-libhatchery.so ()
  (cffi:load-foreign-library
   #p"~/quicklisp/local-projects/roper/build/libhatchery.so"))
;; may need to change this, depending on where things are.

#+sbcl
(sb-ext:unlock-package :sb-vm)

;;#+sbcl
;;(import '(sb-assem:inst sb-vm::make-ea)) 


;; calculate the euclidean distance between two points
;; in an n-dimensional space. 


(export 'pick)
(defmacro pick (seq)
  `(elt ,seq (random (length ,seq))))



;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

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
(defdelim #\[ #\] (bytes)
  ;; (let ((stuff (if (listp (symbol-value (car bytes)))
  ;;                  (apply #'values (car bytes))
  ;;                  bytes)))
  ;;  (print bytes) (print stuff)
    (make-array (length (symbol-value bytes)) :element-type '(unsigned-byte 8)
                :initial-contents (symbol-value bytes)))


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

(defun dump (seq &optional len)
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


(export 'hexify)
(defun hexify ()
  (setq *print-base* (if (= #x10 *print-base*) #xa #x10))
  (setq *read-base* (if (= #x10 *read-base*) #xa #x10))
  (format t "setting *print-base* and *read-base* to #x~x, #x~x...~%"
          *print-base* *read-base*))


(defun swap-at (list i j)
            (let ((tmp (elt list i)))
              (setf (elt list i) (elt list j)
                    (elt list j) tmp)))

(defun flip-words (list)
            (loop for word on list by #'cddddr do
                 (swap-at word 0 3)
                 (swap-at word 1 2)))

(defun chomp (str)
  (string-trim '(#\newline #\space #\linefeed #\tab) str))

(defun hvals (hashmap)
  (loop for v being the hash-values in hashmap collect v))

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(defun list->bytevec (code)
  (make-array (length code) :element-type '(unsigned-byte 8)
              :initial-contents code))


(defun unsanitary-p (bytes)
  (let ((flag) (res))
    (loop for byte in bytes do
         ;; #x23 = ., and #x2E = # ;; We're detecting read macros here. 
         (when flag (if (= byte #x23) (progn (setf res t) (return)) (setf flag nil)))
         (when (= byte #x2E) (setf flag t)))
    res))

(defun bytes->sexp (bytes)
  (let ((string (coerce (mapcar #'code-char bytes) 'string)))
    (if (unsanitary-p bytes)
        (format t "POSSIBLE ATTACK DETECTED: ~A~%" string)
        (read-from-string string))))

(defun sexp->bytes (sexp)
  ;; mostly just for testing bytes->sexp
  (let ((string (format nil "~S" sexp)))
    (mapcar #'char-code (coerce string 'list))))
