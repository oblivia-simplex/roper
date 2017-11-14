(in-package :read-elf)

(export '(section
	  build-section
	  sec-name
	  sec-data
	  sec-words
	  sec-addr))
(defstruct (section
            (:conc-name sec-)
            (:constructor build-section
                (&key (bytes #())
                   (address 0)
;                   (perms '(:read :write :exec))
                   (named "UNKNOWN"))))
  (name (intern (string-upcase named) :keyword) :type symbol)
  (data (make-array (length bytes)
                    :element-type '(unsigned-byte 8)
                    :initial-contents bytes)
   :type (array (unsigned-byte 8)))
  (words (let ((words (bytes->dwords bytes)))
	   (make-array (length words)
		       :element-type '(unsigned-byte 32)
		       :initial-contents words))
	 :type (array (unsigned-byte 32)))
  ;; parameterize word width. this is a shortcut for now. 
  (addr address :type integer))
;  (perm perms :type (cons keyword)))

(export 'word-at)
(defun word-at (section address &optional (width 4))
  (when (<= (sec-addr section)
            address
            (1- (+ (sec-addr section)
                   (length (sec-data section)))))
    ;;(aref (sec-words section)
    ;;      (floor (/ (- address (sec-addr section)) width)))))
    (bytes->dword (sec-data section)
                  :offset (- address (sec-addr section))
                  :width width)))

(export '(segment
	  seg-addr
	  seg-size
	  seg-perm))
(defstruct (segment (:conc-name seg-))
  (addr 0 :type integer)
  (size 0 :type integer)
  (perm '(:read :write :exec) :type (or nil (cons keyword))))

(defun segments-overlap (s1 s2)
  (> (+ (seg-addr s1) (seg-size s1))
     (seg-addr s2)))

(defun %merge-segments (s1 s2)
  (format t "Merging:~%~S~%~S~%" s1 s2)
  (make-segment :addr (seg-addr s1)
                :size (- (+ (seg-addr s2)
                            (seg-size s2))
                         (seg-addr s1))
                :perm (remove-duplicates
                       (concatenate
                        'list
                        (seg-perm s1)
                        (seg-perm s2)))))
;; TODO: do this properly, in log n time, using a mergesort-like
;; strategy. This linear sweep is dumb and lazy. 
(defun merge-segments (seglist)
  (let* ((sorted (sort seglist #'< :key #'seg-addr))
         (merged ())
         (head (car sorted)))
    (loop for s on (cdr sorted) do
      (if (segments-overlap head (car s))
          (setq head (%merge-segments head (car s)))
          (progn
            (format t "No collision. Storing head.~%")
            (push head merged)
            (setq head (car s)))))
    (push head merged)
    (reverse merged)))


(defun format-elf-section (sec)
  (let* ((name (elf:name sec))
         (hdr (elf:sh sec))
;;         (perms (expand-flags (elf:flags hdr)))
         (addr (if hdr (elf:address hdr) -1)) ;; double check this
         (data (elf:data sec)))
    (build-section :bytes data
                   :address addr
    ;               :perms perms
                   :named name)))

(defun page-align (n)
  (logand n #xFFFFF000))

;; NB: Unicorn inverts the order of the permission bits used here.
;; This is another good reason, besides readability, for using
;; an abstraction layer.
(defun expand-flags (n)
  (let ((flags '(:exec :write :read)))
    (mapcar (lambda (i) (elt flags i))
            (remove-if (lambda (x) (zerop (ldb (byte 1 x) n)))
                       '(0 1 2)))))

(defun format-elf-segment (ph &key (align))
  (let* ((perms (expand-flags (elf:flags ph)))
         (addr (elf:vaddr ph))
         (size (elf:memsz ph)))
    (when align
      (setq addr (page-align addr))
      (setq size (+ #x1000 (page-align size)))) ;; make up for loss in page-align
    (make-segment :addr addr
                  :size size
                  :perm (if (null perms) '(:read :write :exec) perms))))

(defun get-loadable-elf-segments (elf-obj &key (align t))
  (mapcar (lambda (s) (format-elf-segment s :align align))
          (remove-if-not
           (lambda (x)
             (eq :LOAD (elf:type x)))
           (elf:program-table elf-obj))))

(defun get-elf-sections (elf-obj)
  (remove-if #'null
             (mapcar (lambda (s)
                       (unless (consp (elf:data s)) ;; lazy hack
                         (format-elf-section s)))
                     (elf:sections elf-obj))))

(defun sec-in-seg (sec seg)
  (<= (seg-addr seg)
      (sec-addr sec)
      (+ (sec-addr sec) (length (sec-data sec)))
      (+ (seg-addr seg) (seg-size seg))))

;; return a list of the sections that can be mapped to some segment
;; in a list of segments
(defun secs-in-segs (secs segs)
  (remove-if-not (lambda (s)
                   (some (lambda (g)
                          (sec-in-seg s g))
                        segs))
                 secs))


(in-package :elf)

;; add functions for pulling register info out of core files

