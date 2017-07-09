(in-package :roper)

;; some handy testing values
(defparameter *elf* (elf:read-elf "/home/oblivia/Projects/roper/data/tomato-RT-AC3200-ARM-132-AIO-httpd"))

(setq *print-base* 16)

;; convenience function
(defun text-sec (path)
  (find :.text (read-elf:get-elf-sections (elf:read-elf path))
        :key #'read-elf::sec-name))

(defparameter *test-text* (text-sec "/home/oblivia/Projects/roper/data/tomato-RT-AC3200-ARM-132-AIO-httpd"))

(defparameter *constants* '(#xdeadbeef
			    #xbabababa
			    #x00000001
			    #xF0F0F0F0
			    #x00000002))

(defparameter *population* (init-population :section *test-text* 
					    :constants *constants*
					    :number #x1000))

(defparameter *uc* (init-engine :arm :arm *elf*))

(defparameter *specimen* (elt (pop-deme *population*) 50))
