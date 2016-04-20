(in-package :roper-pkg)

(defparameter *debug* t)


;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; global lookup tables and the like
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(defvar *gadmap* (make-hash-table :test #'eql))

;; note that gadgets% has almost exactly the same structure as strings
;; is there some common idiom here that we could abstract into a macro?
;; or would that just make it more complicated?
(defparameter *x86-ret* '(#xc3))

(export 'retp)
(defun retp (byte)
  (member byte *x86-ret*))

(defparameter *gadget-length* 32)

(defparameter *x86-reg-count* 26) ;; machine dependent

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; using the elf package
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


(defun int-arm-pop-pc-p (opcode)
  (and
   ;; is it a pop?
   (= (print (logand opcode #xFFFF0000)) #xe8bd0000)
   ;; does it pop into register 15 (pc)?
   (/= (print (logand opcode (ash 1 15))) 0 )))

(defun arm-pop-pc-p% (bytes)
  ;; works backwards
  (and
   (= (elt bytes 0) #xe8)
   (= (elt bytes 1) #xbd)
   (/= (logand (elt bytes 2)
               (ash 1 7))
       0)))


(defun extract-text (elf-obj)
  "Returns the text section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (let* ((secs (elf:sections elf-obj))
         (addrs (mapcar #'elf:address (elf:section-table elf-obj)))
         (text-idx (position ".text" secs
                             :key #'elf:name :test #'equalp)))
    (values (elf:data (elt secs text-idx))
            (elt addrs text-idx))))


;; this only works for 1 byte return instructions.
;; modify it, using a trick like lastword in the C
;; counterpart. 
(defun gadmap-x86% (bytes start &key (glength *gadget-length*))
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


;; branch instructions have the most significant byte #xeb
;; scan for these and avoid inside gadgets for now.
;; blx have #xe12f (#x2f #xe1) in their most significant half
;; word
(defun gadmap-arm% (bytes start &key (glength *gadget-length*))
  (let ((tyb (reverse (coerce bytes 'list)))
        (end (1- (+ start (length bytes))))
        (found 0)
        (gadmap (make-hash-table)))
    (loop
       for code on tyb by #'cddddr
       and i = 0 then (+ i 4) do
         (when (arm-pop-pc-p% (subseq code 0 4))
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
                 
(defun gadmap (elf &key (glength *gadget-length*) (arch :arm))
  (multiple-value-bind (text addr)
      (extract-text elf)
    (case arch
      ((:x86) (gadmap-x86% text addr :glength glength))
      ((:arm) (gadmap-arm% text addr :glength glength)))))
             
(defun file->gadmap (filename &key (arch :arm) (gadget-length *gadget-length*))
  (gadmap (elf:read-elf filename) :glength gadget-length :arch arch))
   
(defun gadgets%% (elf-section &optional (gadlen *gadget-length*))
  (gadgets% (coerce (elf:data elf-section) 'list) gadlen))


;; ------------------------------------------------------------
;; too ugly to live: ;; and only relevant to x86 arch
(defun last3let (str) (subseq str (- (length str) 4)
                              (1- (length str))))

(defun ends-with-ret-p (gadget)
  (string= (last3let (dump gadget)) "RET"))

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


(defun has-bad-inst-p (gadget)
  ;; detects gadgets that have instructions I don't yet know how
  ;; best to deal with
  ;; first, let's catch jumps and calls
  (let ((bad '("J" "CALL" "POP" "PUSH" "SP" "IP" "["))
        (disas (dump gadget)))
    (or (block check
          (loop for b in bad do
               (if (search b disas) (return-from check T) nil)))
        nil)))      

;; end too ugly to live section
;; ------------------------------------------------------------

(defun disas-inst (code)
  "Intended for disassembly of single instructions. Only for native
arch. "
  (let ((dis (cffi-objdump code)))
    (chomp (subseq dis (- (length dis) 10) (length dis)))))
  
;; (defun ret-filter% (gadgets)
;;   (remove-if-not #'cdr (mapcar #'shrink-gad gadgets)))


(defvar *arm-nop* '(#x00 #x00 #x00 #x00))
(defvar *x86-nop* '(#x90))

(defun concat (gadget-list &key (arch :arm))
  "Concatenates gadgets, removing the *ret* instruction at the end,
first, to approximate executing them in sequence. Mostly just for
testing."
  (flet ((crop (l)
           (append
            (subseq l 0 (- (length l)
                           (if (eq arch :arm) 4 1)))
            (if (eq arch :arm) *arm-nop* *x86-nop*))))

    (concatenate 'list
     (reduce #'(lambda (x y) (concatenate 'list x y))
             (mapcar #'crop (butlast gadget-list)))
     (car (last gadget-list)))))

(defun incarnate (chain &key (ht *gadmap*))
  (let ((keylist (chain-addr chain)))
    (if (cdr keylist)
        (concat (mapcar #'(lambda (x) (gethash x ht)) keylist))
        (gethash (car keylist) ht))))
    

(defparameter *code-server-port* 9999)

;;(ql:quickload :iolib)

(defun dispatch (code &key (ip #(127 0 0 1))
                        (port *code-server-port*)
                        (header '(#x10)))
  (let* ((len (elf:int-to-bytes (length code) 2))
         (code-arr (make-array (+ 3 (length code)) ;; should already be this
                               :element-type '(unsigned-byte 8)
                               :initial-contents
                               (concatenate 'list header len code))))
     (iolib:with-open-socket (socket :connect :active
                                     :address-family :internet
                                     :type :stream
                                     :ipv6 :nil)
       (iolib:connect socket 
                      (iolib:lookup-hostname ip)
                      :port port :wait t)
       (iolib:send-to socket code-arr)
       ;; MASSIVE security hole! The server can send back read macros
       ;; using the #. dispatch string, and execute arbitrary code
       ;; on the lisp client.
       ;; solution: sanitize the socket input before passing it to
       ;; #'read!
       (read socket))))


;; todo: find a way of handling branches. maintain the entire image of
;; the code, and send addresses to the emulator? let the emulator
;; request code for jump targets, or maintain a static image of the
;; code on that end as well?

(defun init-gadmap (path &key (gadget-length *gadget-length*))
  (setf *gadmap* (file->gadmap path :gadget-length gadget-length)))



;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; =-=                      Genetic operations                     =-=
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

;; Fitness-related:
(defvar *target*)

(defun init-gadmap (path &key (gadget-length *gadget-length*))
  (setf *gadmap* (file->gadmap path :gadget-length gadget-length) ))

(defvar *wordsize* 32) ;; for arm

(defun distance (vec1 vec2)
  (flet ((chop (n)
           (ldb (byte *wordsize* 0) n)))
    (sqrt
     (reduce #'+
           (loop for i below (length vec1) collect
                (expt (- (chop (elt vec1 i))
                         (chop (elt vec2 i)))
                      2))))))

(defun pattern->idxlist (pattern)
"A pattern is a vector consisting of unsigned word-sized integers and
wildcard symbols _. Returns a cons pair whose first element is a list
of the positions of nonwildcard values in the pattern, and whose
second element is a list of the target values."
  (let ((pos))
    (loop
       for mark across pattern
       for i from 0 do
         (unless (eq mark '_) (push i pos)))
    (cons
     (reverse pos)
     (mapcar #'(lambda (x) (elt pattern x)) pos))))
       

(defun match-pat (pattern regvec)
  (assert (<= (length pattern) (length regvec)))
  (match (pattern->idxlist pattern) regvec))

;; This will be the fitness function.
;; we'll use a default pattern and idxlist for testing. 
(defun match (idxlist regvec)
  (let ((target (cdr idxlist))
        (result (loop for i in (car idxlist)
                   collect (aref regvec i))))
    (distance target result)))

(defun init-target (pattern)
  (setf *target* (pattern->idxlist pattern)))

(defun test-chain (chain &key
                           (target *target*)
                           (arch :arm))
  (let* ((result (dispatch
                  (incarnate chain)
                  :header (if (eq arch :arm)
                              '(#x10)
                              '(#x00))))
         (fitness (match target result)))
    (if *debug* (format t "ADDRESSES: ~A~%CHAIN:~%~A~%RESULT:~A~%MATCH: ~F~%"
                        (chain-addr chain) (incarnate chain)
                        result fitness))
    (setf (chain-fit chain) fitness)))


;; ------------------------------------------------------------
;; population control
;; ------------------------------------------------------------

(defvar *population*)

(defstruct chain addr fit)


(defun init-pop (&key (max-start-len 5)
                    (ht *gadmap*))
  ;; include all singleton chains in the pop,
  ;; and just as many small combos
  (let ((keys (loop for k being the hash-keys in ht collect k)))
    (setf *population*
          (mapcar (lambda (g) (make-chain :addr g))
                  (append
                   (mapcar #'list keys) ;; singleton chains
                   (loop repeat (length keys) collect
                        (loop repeat (1+ (random max-start-len))
                           collect
                             (pick keys))))))))


(defun everything ()
  "for debugging purposes. get everything to a testable state."
  (init-target #(0 _ _ #x10 _ _ #x111))
  (init-gadmap #P"~/Projects/roper/bins/arm/ldconfig.real" :gadget-length *gadget-length*)
  (init-pop))
  
  

;; Todo:
;; * pass starting address in header along to hatchsock
;; * detect and report infinite loops. kill offending gadgets
;;  -- remove from hashtable, and delete any members of population
;;     that use those contraband gadgets
;;  -- perhaps do the same for other hard-to-fix errors
;; * pass a stack along with the gadget. (advanced, save for later)
  





