(in-package :roper)

;; some handy testing values
(defparameter *elf* (elf:read-elf "/home/oblivia/Projects/roper/data/tomato-RT-AC3200-ARM-132-AIO-httpd"))

(setq *print-base* 16)

(defparameter *test-elf-sections*
  (read-elf:get-elf-sections *elf*))

;; convenience function
(defun get-sec (elf sec-symbol)
  (find sec-symbol (read-elf:get-elf-sections elf)
        :key #'read-elf::sec-name))

(defparameter *test-text* (get-sec *elf* :.text))

(defparameter *test-rodata* (get-sec *elf* :.rodata))

;; (defparameter *constants* '(#xdeadbeef
;; 			    #xbabababa
;; 			    #x00000001
;; 			    #xF0F0F0F0
;; 			    #x00000002))

;; (defparameter *population* (init-population :section *test-text* 
;; 					    :constants *constants*
;; 					    :number #x1000))

;; (defparameter *uc* (init-engine :arm :arm *elf*))

;; (defparameter *specimen* (elt (pop-deme *population*) 50))

;; push units

(defparameter *gadgets*
  (label-list :gadget (find-gadgets *test-text*)))

(defparameter *ints*
  (label-list :int (range 0 32)))

(defparameter *pointers* (label-list :pointer (coerce (sec-words *test-rodata*)
						      'list)))

(defparameter *dwords* (label-list :bool '(#xdeadbeef
					   #xFFFF0000
					   #x0000FFFF
					   #xF0F0F0F0
					   #x00000001
					   #x00000000
					   #x00000002)))

(defparameter *bool* (label-list :bool '(t nil)))

(defparameter *list* '(:list . ()))



