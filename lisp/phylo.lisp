;; *******************
;; Phylogenetic client
;; *******************

(in-package :roper)

(defparameter *debug* t)

(defparameter *default-ip* #(#10r127 0 0 1))
(defparameter *default-port* #(#10r9999))

;; == constants, which var vars only b/c that makes slime happy ==

(defstruct chain addr fit res)

(defvar *arm-nop* '(#x00 #x00 #x00 #x00))
(defvar *x86-nop* '(#x90))
(defvar *word-in-bytes* 4)
(defvar *word-in-bits* (* *word-in-bytes* 4)) ;; for arm
(defparameter *code-server-port* 9999)
(defparameter *x86-ret* '(#xc3))
(defun retp (byte)
  (member byte *x86-ret*))
(defparameter *gadget-length* 32)
(defparameter *x86-reg-count* 26) ;; machine dependent
;; genetic parameters
(defparameter *mutation-vs-crossover-rate* 0.5)

;; == variables initialized once, and then read globally == 
(defvar *target*)

;; == variables both written to and read from globally ==
;; == these will need to be either mutexed or refactored ==
;; == if threading is used.
(defvar *best* nil)
(defvar *population*)
(defvar *gadmap* (make-hash-table :test #'eql))
;;(ql:quickload :iolib)
(defvar *elf*)



;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; global lookup tables and the like
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=



;; note that gadgets% has almost exactly the same structure as strings
;; is there some common idiom here that we could abstract into a macro?
;; or would that just make it more complicated?

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; Extracting ROP gadgets and preparing the payload for the hatchery
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


(defun init-elf (path)
  (setf *elf* (elf:read-elf path)))

(defun extract-text (elf-obj)
  ;; deprecated. use extract-by-name from now on. 
  "Returns the text section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (multiple-value-bind (data addr)
      (extract-by-name elf-obj ".text")
    (values data addr)))

(defun extract-by-name (elf-obj name)
    "Returns a named section as a vector of bytes, and the address at
which the text section begins, as a secondary value."
  (let* ((secs (elf:sections elf-obj))
         (addrs (mapcar #'elf:address (elf:section-table elf-obj)))
         (named-idx (position name secs
                             :key #'elf:name :test #'equalp)))
    (values (elf:data (elt secs named-idx))
            (elt addrs named-idx)))) ;; ???? +1


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
        (end (+ start (length bytes)))
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

  
;; (defun ret-filter% (gadgets)
;;   (remove-if-not #'cdr (mapcar #'shrink-gad gadgets)))

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


(defun make-header (&key
                      (reset_data 0)
                      (set_data 0)
                      (reset_reg 0)
                      (feedback_sexp 1)
                      (archflag 1) ;; 1 for arm
                      (modeflag 0) ;; for arm mode or 64 bit x86
                      (executable 1) ;; for yes
                      (writeable 1) ;; for yes
                      (expect 0) ;; a three-byte number (< 2^24)
                      (startat 0)) ;; a four-byte number (< 2^32)
  "Returns an array of bytes that encodes these attributes as a header."
  (let* ((header (make-array '(8)
                             :element-type '(unsigned-byte 8)
                             :initial-element 0))
         (expect_size 3)
         (startat_size 4)
         (expect_bytes (elf:int-to-bytes expect expect_size))
         (startat_bytes (elf:int-to-bytes startat startat_size)))
    (setf (aref header 0)
          (logior set_data
                  (ash reset_reg 1)
                  (ash reset_data 1)
                  (ash feedback_sexp 2)
                  (ash archflag 3)
                  (ash modeflag 5) ;; bit 4 reserved
                  (ash executable 6)
                  (ash writeable 7))) ;; and that takes care of byte 0
    (setf (subseq header 1 (1+ expect_size)) expect_bytes)
    (setf (subseq header (1+ expect_size) (+ expect_size startat_size 1))
          startat_bytes)
    header))
          
        
                            

(defun stack->bytes (stack &key (word-in-bytes *word-in-bytes*))
  (reduce #'(lambda (x y) (concatenate 'list x y))
          (mapcar #'(lambda (z) (elf:int-to-bytes z word-in-bytes)) stack)))




(defun dispatch (payload &key (ip #(#10r127 0 0 #10r1))
                           (port *code-server-port*))
  (iolib:with-open-socket (socket :connect :active
                                  :address-family :internet
                                  :type :stream
                                  :ipv6 :nil)
    (iolib:connect socket 
                   (iolib:lookup-hostname ip)
                   :port port :wait t)
    (iolib:send-to socket payload)
    ;; MASSIVE security hole! The server can send back read macros
    ;; using the #. dispatch string, and execute arbitrary code
    ;; on the lisp client.
    ;; solution: sanitize the socket input before passing it to
    ;; #'read!
    (read socket)))

(defparameter *header-length* 8)
(defun dispatch-stack (stack-of-addrs &key (ip #(#10r127 0 0 1))
                                        (port *code-server-port*)
                                        (reset_reg 0)
                                        (feedback_sexp 1)
                                        (archflag 1) ;; 1 for arm
                                        (modeflag 0)) ;;for arm mode or 64 bit x86
  (let* ((size (+ *header-length*
                  (* (length stack-of-addrs) 4)))
         (header (make-header :reset_data 0
                              :reset_reg reset_reg
                              :expect (- size *header-length*)
                              :feedback_sexp feedback_sexp
                              :archflag archflag
                              :modeflag modeflag))
         (stack (stack->bytes stack-of-addrs))
         (payload (make-array `(,size)
                              :element-type
                              '(unsigned-byte 8)
                              :initial-contents
                              (concatenate 'list header stack))))
    (format t "STACK: ~A~%HEADER: ~A~%SIZE: ~A~%EXPECT: ~A~%"
            stack-of-addrs header size (- size *header-length*))
    (dispatch payload :ip ip :port port)))


(defun dispatch-section (name-of-section &key
                                           (elf *elf*)
                                           (ip #(#10r127 0 0 1))
                                           (port *code-server-port*)
                                           (reset_data 0)
                                           (archflag 1)
                                           (modeflag 0))
  (multiple-value-bind (data addr)
      (extract-by-name elf name-of-section)
    (let* ((size (+ *header-length* (length data)))
           (header (make-header :set_data 1
                                :reset_data reset_data
                                :feedback_sexp 0
                                :startat addr
                                :expect (- size *header-length*)
                                :archflag archflag
                                :modeflag modeflag))
           (payload (make-array `(,size)
                                :element-type
                                '(unsigned-byte 8)
                                :initial-contents
                                (concatenate 'list header data))))
      (format t "HEADER: ~A~%SIZE: ~D~%EXPECT: ~D~%"
              header size (- size *header-length*))
      (dispatch payload :ip ip :port port))))

                               
                   

;; note that the header protocol is unstable right now, and between
;; two different formats. this function uses the old one, but i expect
;; to deprecate it in favour of stack-based dispatches, in any case.
(defun dispatch-code (code &key (ip #(#10r127 0 0 #10r1))
                             (port *code-server-port*)
                             (header '(#x12))
                             (start-at #x1000))
  (let* ((len (elf:int-to-bytes (length code) 2))
         (start (elf:int-to-bytes start-at *word-in-bytes*))
         (code-arr (make-array (+ 3 *word-in-bytes* (length code)) ;; should already be this
                               :element-type '(unsigned-byte 8)
                               :initial-contents
                               (concatenate 'list
                                            header
                                            len
                                            start
                                            code))))
    (dispatch code-arr :ip ip :port port)))


;; todo: find a way of handling branches. maintain the entire image of
;; the code, and send addresses to the emulator? let the emulator
;; request code for jump targets, or maintain a static image of the
;; code on that end as well?

(defun init-gadmap (path &key (gadget-length *gadget-length*))
  (setf *gadmap* (file->gadmap path :gadget-length gadget-length)))


;; map each address in the gadmap to the stack-pointer delta -- how
;; many pushes and pops does it have? +1 for each pop, -1 for each
;; push. So far, we've been assuming every gadget has -1, as a
;; temporary simplification technique. But this won't do.
(defun arm-pop-p% (bytes)
  (and
   (= (elt bytes 0) #xe8)
   (= (elt bytes 1) #xbd)))

(defun arm-push-p% (bytes)
  (and
   (= (elt bytes 0) #xe9)
   (= (elt bytes 1) #x2d)))
;; double check these opcodes


(defun push-p (x &key (arch :arm))
  
  )




(defun pop-p (x &key (arch :arm))
  
  )

 
(defun bytes->words (bytes word-in-bytes)
  (loop for b on bytes by (lambda (w) (nthcdr word-in-bytes w))
     collect (subseq b 0 word-in-bytes)))

(defun riscword (arch)
  (case arch
    ((:arm) 4)
    ((:thumb) 2)
    (:default nil)))

(defun sp-delta (gadaddr &key (gadmap *gadmap*)
                               (arch :arm))
  (let* ((gadget (gethash gadaddr gadmap))
         (gadwords (bytes->words gadget (riscword arch)))
         (pushes (length (remove-if-not
                          (lambda (x) (push-p x :arch arch)) gadwords)))
         (pops (length (remove-if-not
                        (lambda (x) (pop-p x :arch arch)) gadwords))))
    (- pops pushes)))
   

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; =-=                      Genetic operations                     =-=
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

;; Fitness-related:


(defun distance (vec1 vec2)
  (flet ((chop (n)
           (ldb (byte *word-in-bits* 0) n)))
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
         (unless (eq mark '_) (push (cons i mark) pos)))
    (reverse pos)))

(defun match-pat (pattern regvec)
  (assert (<= (length pattern) (length regvec)))
  (match (pattern->idxlist pattern) regvec))

;; This will be the fitness function.
;; we'll use a default pattern and idxlist for testing. 
(defun match (target regvec)
  (let ((vals (mapcar #'cdr target))
        (result (loop for i in (mapcar #'car target)
                   collect (aref regvec i))))
    (distance vals result)))

           

(defun init-target (pattern)
  (setf *target* (pattern->idxlist pattern)))

(defun test-chain (chain &key 
                           (arch :arm)
                           (ip #(#10r127 0 0 1))
                           (port 9999)
                           (activity-test nil))
  (let ((result)
        (archheader (if (eq arch :arm) #x10 #x00)))
    (when *debug*
      (format t "~%--------------------------------------~%TESTING CHAIN OF ~D GADGETS~%--------------------------------------~%"
              (length (chain-addr chain))))
    (loop
       for gadget on (chain-addr chain) do
         (setf result
               (dispatch-code (gethash (car gadget) *gadmap*)
                              :ip ip
                              :port port
                              :header (list (logior
                                             archheader
                                             (if result 0 2)
                                             (if (cdr gadget) 0 4)
                                             (if activity-test 8 0)))
                              :start-at (car gadget)))
         (if *debug* (format t "ADDRESS: ~X~%RESULT: ~A~%"
                             (car gadget)
;;                             (gethash (car gadget) *gadmap*)
                             result)))
    result))

(defvar *register-count* 15)
(defparameter *activity-test-pattern*
  (coerce (loop repeat *register-count*
             collect #x02020202) 'vector))

(defun activity-test (chain &key
                              (arch :arm)
                              (ip #(#10r127 0 0 1))
                              (port #10r9999))
  (not (equalp *activity-test-pattern*
               (test-chain chain :arch arch
                           :ip ip :port port
                           :activity-test t))))

(defun cull-the-idle (&key (arch :arm)
                        (ip *default-ip*)
                        (port *default-port*)
                        (population *population*))
  (setf population
        (remove-if-not #'(lambda (x)
                           (activity-test x :arch arch
                                          :ip ip
                                          :port port)))))
                                               

;; ------------------------------------------------------------
;; population control
;; ------------------------------------------------------------




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

;; ------------------------------------------------------------
;; mutation operators
;; ------------------------------------------------------------

(defun mut-push-gadget (chain)
  (push (pick (loop for k being the hash-keys in *gadmap* collect k))
        (chain-addr chain))
  chain)

(defun mut-pop-gadget (chain)
  (when (cdr (chain-addr chain))
    (pop (chain-addr chain)))
  chain)

(defun mut-shuffle-gadgets (chain)
  (setf (chain-addr chain) (shuffle (chain-addr chain)))
  chain)

(defun mut-shrink-gadget (chain)
  (let* ((addr (pick (chain-addr chain)))
         (gadget (gethash addr *gadmap*))) ;; about to do something non-threadsafe
    (print addr)
    (setf (chain-addr chain)
          (delete addr (chain-addr chain)))   
    (setf addr (+ addr *word-in-bytes*))
    (pop gadget)
    (if (cdr gadget)
        (progn
          (setf (gethash addr *gadmap*) gadget)
          (push addr (chain-addr chain)))
        (mut-push-gadget chain)))
  chain);; replace with random if exhausted

(defparameter *mut-vec*
  #(mut-push-gadget
    mut-pop-gadget
    mut-shuffle-gadgets
    mut-shrink-gadget))

(defun random-mutation (chain)
  (funcall (print (pick *mut-vec*)) chain))

(defun crossover (chain1 chain2)
  "One-point crossover."
  (let ((idx1 (random (length (chain-addr chain1))))
        (idx2 (random (length (chain-addr chain2)))))
    (values
     (make-chain
      :addr (append (subseq (chain-addr chain1) 0 idx1)
                    (subseq (chain-addr chain2) idx2)))
     (make-chain
      :addr (append (subseq (chain-addr chain2) 0 idx2)
                    (subseq (chain-addr chain1) idx1))))))




(defun mate (parent1 parent2)
  (cond ((< (random 1.0) *mutation-vs-crossover-rate*)
         (multiple-value-bind (child1 child2)
           (crossover parent1 parent2)
           (if *debug* (print 'crossover))
           (values child1 child2)))
        (:OTHERWISE
         (let ((child1 (make-chain :addr (copy-seq (chain-addr parent1))))
               (child2 (make-chain :addr (copy-seq (chain-addr parent2)))))
           (if *debug* (print 'mutating))
           (setf child1 (random-mutation child1))
           (setf child2 (random-mutation child2))
           (values child1 child2)))))
               
      

(defun lexicase (tsize population &key (ip *default-ip*)
                                    (port *default-port*))
  (let ((contenders
         (subseq (shuffle (copy-seq population)) 0 tsize))
        (targets (shuffle (copy-seq *target*)))
        (mother (cons nil nil))
        (father (cons nil nil)))
    (loop for chain in contenders do
         (when (null (chain-res chain))
           (setf (chain-res chain)
                 (test-chain chain :ip ip :port port))))
    (if *debug* (format t "LEXICASE FILTERING...~%"))
    (loop for aims in (list targets (reverse targets))
       for parent in (list (cons mother nil) (cons father nil)) do
         (loop for point in targets do
              (let ((next)
                    (score (length targets)))
                (format t "TESTING POINT ~A~%" point)
                (loop for chain in contenders do
                     (if (= (elt (chain-res chain) (car point))
                            (cdr point))
                         (push chain next)))
                (and *debug* (format t "REMAINING: ~D~%" (length next)))
                (when (cddr next) ;; if there are <= 2 chains left
                  (decf score)
                  (mapc (lambda (x) (setf (chain-fit x) score)) next)
                  (and *debug* (format t "SCORE: ~D~%" score))
                  (when (zerop score)
                    (format t "PERFECT SPECIMEN FOUND: ~A~%"
                            (car contenders))
                    (setf *best* (car contenders)))
                  (setf contenders next)
                  (setf next nil))))
         (setf (caar parent) (car contenders)))
    (when *debug*
      (format t "MOTHER: ~A~%FATHER: ~A~%" mother father))
    ;; now we have two parents
    (multiple-value-bind (child1 child2)
        (mate (car mother) (car father))
      (test-chain child1 :ip ip :port port)
      (test-chain child2 :ip ip :port port)
      (nsubst child1 (caddr contenders) population)
      (nsubst child2 (caddr contenders) population))))



            
            
    



(defun tournement (tsize population &key(ip *default-ip*)
                   (port *default-port*) (target *target*))
  (let ((contenders (subseq (shuffle (copy-seq population)) 0 tsize)))
    (loop for chain in contenders do
         (cond ((null (chain-res chain))
                (setf (chain-res chain)
                      (test-chain chain :ip ip :port port))
                (setf (chain-fit chain)
                      (match target (chain-res chain)))
                (if (or (null *best*)
                        (< (chain-fit chain) (chain-fit *best*)))
                    (setf *best* chain)))
               (:OTHERWISE
                (unless (chain-fit chain)
                  (setf (chain-fit chain)
                        (match target (chain-res chain))))
                (and *debug*
                     (format t "ALREADY TESTED ~A~%" chain)))))
    (setf contenders (sort contenders #'(lambda (x y)
                                          (< (chain-fit x)
                                             (chain-fit y)))))
    (multiple-value-bind (child1 child2)
        (mate (first contenders) (second contenders))
      (test-chain child1 :ip ip :port port)
      (test-chain child2 :ip ip :port port)
      (nsubst child1 (caddr contenders) population)
      (nsubst child2 (caddr contenders) population))))
    

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; testing and debugging functions
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(defun everything ()
  "for debugging purposes. get everything to a testable state."
  (setf *best* nil)
  (init-target #(1 _ _ #xFF _ _ #x2))
  (init-elf #P"~/Projects/roper/bins/arm/ldconfig.real")
  (init-gadmap #P"~/Projects/roper/bins/arm/ldconfig.real" :gadget-length *gadget-length*)
  (init-pop))
  
  

;; Todo:
;; * pass starting address in header along to hatchsock
;; * detect and report infinite loops. kill offending gadgets
;;  -- remove from hashtable, and delete any members of population
;;     that use those contraband gadgets
;;  -- perhaps do the same for other hard-to-fix errors
;; * pass a stack along with the gadget. (advanced, save for later)
  





