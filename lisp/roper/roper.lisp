(in-package :roper)



(defun extract-gadgets-from-elf (elf-path &key (save-path))
  (let* ((elf-obj (elf:read-elf elf-path))
	 (secs (read-elf:get-elf-sections elf-obj))
	 (text (find :.text secs :key #'read-elf:sec-name))
	 ;(rodata (find :.rodata secs :key #'read-elf:sec-name))
	 (gadgets (find-gadgets text)))
    (when save-path
      (let ((*print-base* 16))
	(with-open-file (s save-path :direction :output :if-exists :overwrite)
	  (format s ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;~%")
	  (format s ";; Gadgets from ~A~%" elf-path)
	  (format s ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;~%")
	  (loop for g in gadgets do
	       (format s "~S~%" g))
	  (format t "~D gadgets saved to ~A~%"
		  (length gadgets)
		  save-path))))
    gadgets))

(defun load-constants-from-file (path &key (base 16))
  (let ((data ())
	(*read-base* base))
    (with-open-file (s path :direction :input)
      (loop for line = (read-line s nil)
	 while line do
	   (let ((sexp (read-from-string line nil)))
	     (when sexp
	       (push sexp data)))))
    data))

(defparameter *number-of-engines* 1) ;; should be a user-set param
;; or be dependent on number of threads

(defparameter *engine-pool*
  (hatchery:init-engines :elf (elf:read-elf <elf-path>)
			 :count *number-of-engines*
			 :arch <cpu-arch>
			 :mode <cpu-mode>
			 :merge t))



;; population is RO while in thread
;; specification also RO while in thread
;; but engines are each RW -- one per thread
(defun dispatch-threads (specificiation population engines)
  (loop for engine in engines do
     ;; dispatch the threaded func
       )
  )


(defstruct (island (:conc-name isle-))
  deme
  engine
  lock)

(defstruct (island-queue (:conc-name iq-))
  islands
  lock
  logger)

;;; now add a mutex check to these operations to make them atomic

(defun iq-update-logs (iq isle)
  )

(defun iq-dequeue (iq)
  ;; maybe get the lock first? 
  (pop (iq-islands iq)))

(defun iq-enqueue (iq isle)
  (iq-update-logs iq isle)
  (setf (iq-islands iq)
	(nconc (iq-islands iq) (list isle))))

(defun iq-ready (iq)
  (car (iq-islands iq)))

(defstruct pier
  crowd
  lock)

(defparameter +sleeptime+ 1/100)

;;; a sketch of the main loop.
;;; start filling in these functions with the meat, and
;;; you should be good to go!
(defun main-loop (elf-path)
  (let* ((gadgets (extract-gadgets-from-elf elf-path))
	 (specification)
	 (population)
	 (engines)
	 (island-queue (build-island-queue population engines))
	 (thread-pool)
	 (pier (make-pier)))
    (prime-queue islands)
    (loop while (stop-condition specification population) do
	 (cond ((iq-ready island-queue)
		(dispatch-thread thread-pool island-queue))
	       (t (sleep +sleeptime+))))))
;; update- functions should be modelled after what we did in rust,
;; which worked fairly nicely. 
;; BUT... the downside was that we had to wait for all threads to join
;; before updating anything. maybe the GENLIN approach is better?
;; * form islands (subpop/engine pairs), plus one pier
;; * periodic migration between islands via mutexed pier.
;; * maintain queue of ready islands. when a thread is available, it
;;   grabs an island and works it.
;; * global statistics can be processed while the island is in the queue
;;   and logging can take place here as well. any brief, unthreaded ops. 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; At this point, this file just sets up some basic test-run stuff.  ;;
;; a proper front-end/entry point still needs to be written.         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;






;; (setq *print-base* 16)

;; (defparameter *test-elf-sections*
;;   (read-elf:get-elf-sections *elf*))

;; ;; convenience function
;; (defun get-sec (elf sec-symbol)
;;   (find sec-symbol (read-elf:get-elf-sections elf)
;;         :key #'read-elf::sec-name))

;; (defparameter *test-text* (get-sec *elf* :.text))

;; (defparameter *test-rodata* (get-sec *elf* :.rodata))

;; ;; (defparameter *constants* '(#xdeadbeef
;; ;; 			    #xbabababa
;; ;; 			    #x00000001
;; ;; 			    #xF0F0F0F0
;; ;; 			    #x00000002))

;; ;; (defparameter *population* (init-population :section *test-text* 
;; ;; 					    :constants *constants*
;; ;; 					    :number #x1000))

;; ;; (defparameter *uc* (init-engine :arm :arm *elf*))

;; ;; (defparameter *specimen* (elt (pop-deme *population*) 50))

;; ;; push units

;; (;; defparameter *gadgets*
;; ;;   (label-list :gadget (find-gadgets *test-text*)))

;; ;; (defparameter *ints*
;; ;;   (label-list :int (range 0 32)))

;; ;; (defparameter *pointers* (label-list :pointer (coerce (sec-words *test-rodata*)
;; ;; 						      'list)))

;; ;; (defparameter *dwords* (label-list :bool '(#xdeadbeef
;; ;; 					   #xFFFF0000
;; ;; 					   #x0000FFFF
;; ;; 					   #xF0F0F0F0
;; ;; 					   #x00000001
;; ;; 					   #x00000000
;; ;; 					   #x00000002)))

;; ;; (defparameter *bool* (label-list :bool '(t nil)))

;; ;; (defparameter *list* '(:list . ()))



