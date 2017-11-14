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



