(in-package :junk-drawer)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stringification station
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun list->csv (l &key (fmt "~F"))
  (apply #'concatenate 'string
         (mapcar (lambda (n)
                   (format nil (concatenate 'string fmt ",") n))
                 l)))
