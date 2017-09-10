(in-package :hatchery)

(defun ok! (expression)
  (assert (eq expression :ok)))

(defun mem-map-seg (uc seg)
  (ok! (unicorn::uc-mem-map uc
                   (seg-addr seg)
                   (seg-size seg)
                   (seg-perm seg))))

(defun mem-write-sec (uc sec)
  (ok! (unicorn::uc-mem-write uc
                     (sec-addr sec)
                     (sec-data sec))))


(export '(emu
	  make-emu
	  emu-engine
	  emu-segs
	  emu-secs))
(defstruct emu
  (engine)
  (segs)
  (secs))


(export 'init-engine)
(defun init-engine (&key
		      (arch <cpu-arch>)
		      (mode <cpu-mode>)
		      (elf-obj elf-obj)
		      (merge t))
  (let* ((uc (unicorn::uc-open arch mode))
         (segs%  (get-loadable-elf-segments elf :align t))
	 (segs (if merge (merge-segments segs%) segs%))
         (secs (secs-in-segs (get-elf-sections elf-obj) segs)))
    (mapc (lambda (s) (mem-map-seg uc s)) segs)
    (mapc (lambda (s) (mem-write-sec uc s)) secs)
    (make-emu :engine uc
	      :segs segs
	      :secs secs)))

;; TODO: hatch-chain

(defvar +stop-addr+ #x00000000)
(defparameter +max-steps+ <max-emu-steps>)
(defvar +max-time+  #x10000000)

(export 'get-stack)
(defun get-stack (emu &key (stack-name :.BSS))
  (find stack-name (emu-secs emu) :key #'sec-name))

(export 'get-stack-addr)
(defun get-stack-addr (emu &key (stack-name :.BSS))
  (sec-addr (get-stack emu :stack-name stack-name)))

(export 'get-stack-data)
(defun get-stack-data (emu &key (stack-name :.BSS))
  (sec-data (get-stack emu :stack-name stack-name)))

(defun %counter-cb (uc address size user-data)
  (declare (ignore uc size))
  (format t "Hello from callback! Addr: ~X~%" address)
  (incf (mem-ref user-data :uint64)))

(defparameter &cb (cffi:get-callback (unicorn::fn->callback '%counter-cb)))

;(defun set-cb ()
;  (setq &cb (cffi:get-callback (unicorn::fn->callback '%counter-cb)))
;  t)

;; you're confusing BSS and the stack
;; they're actually different. fix this. 
(export 'hatch-chain)
(defun hatch-chain (&key
                      (emu)
		      (payload)
                      (input)  ;; list of fixnums
                      (inregs <inregs>) ;; list of fixnums -- reg indexes
                      (outregs <outregs>) ;;
                      (reset t)
                      (stack-addr)
                      (stack-ptr)) ;; boolean))
  (let* ((stack-addr (if stack-addr stack-addr
			 (get-stack-addr emu :stack-name :.bss)))
	 (stack-ptr (if stack-ptr stack-ptr stack-addr))
	 (stack-data (if reset (get-stack-data emu :stack-name :.bss) nil))
	 (uc (emu-engine emu))
	 (counter (foreign-alloc :uint64))
         (stack (dwords->bytes payload :endian <endian>))
         (start (car payload))
	 #+unicorn-callbacks
         (cb-handles
	  (progn
	    (loop for ret in (remove-duplicates (chain-rets chain))
	       collect (progn
			 (format t "placing hook at ~X~%" ret)
			 (unicorn::uc-hook-add uc ret (+ ret 4)
					       :callback-ptr &cb
					       :hook-type :code
					       :user-data counter)))))
	 )
    (setf (mem-ref counter :uint64) #x0000000000000000)
    (unicorn::uc-reg-write-batch uc inregs input)
    (when reset
      (ok! (unicorn::uc-mem-write uc stack-addr stack-data)))
    (ok! (unicorn::uc-mem-write uc stack-ptr stack))

    (let* ((error-code (unicorn::uc-emu-start uc start
					      :until +stop-addr+
					      :timeout +max-time+
					      :count +max-steps+))
           (counted (mem-ref counter :uint64))
	   (pc (ldb (byte 32 0) (unicorn::uc-reg-read uc :pc))))
      #+unicorn-callbacks
      (loop for h in cb-handles do
	   (format t "trying to delete cb hook ~S~%" h)
	   (ok! (unicorn::uc-hook-del uc h))
	   ) ;; implement!
      (foreign-free counter)
      ;; returns: register-list, error-code, pc, counted
      (values (mapcar (lambda (x) (ldb (byte 32 0) x))
		      (unicorn::uc-reg-read-batch uc outregs))
              error-code pc counted))))

;; TODO:
;; - implement chain and clump structs, and related functions/methods
;; - unicorn::uc-hook-remove
