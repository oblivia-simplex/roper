(in-package :read-elf)

(defstruct (section
            (:constructor build-section
                (&key (bytes #())
                   (address 0)
                   (perms '(:read :write :exec))
                   (named "UNKNOWN"))))
  (name (intern (string-upcase named)) :type symbol)
  (data (make-array (length bytes)
                    :element-type '(unsigned-byte 8)
                    :initial-contents bytes)
   :type (array (unsigned-byte 8)))
  (addr address :type integer)
  (perm perms :type (cons keyword)))

(defstruct segment
  (addr 0 :type integer)
  (size 0 :type integer)
  (perm '(:read :write :exec) :type (cons keyword)))

(defun format-elf-section (sec)
  (let* ((name (elf:name sec))
         (hdr (elf:sh sec))
         (perms (expand-flags (elf:flags hdr)))
         (addr (elf:address hdr)) ;; double check this
         (data (elf:data sec)))
    (build-section :bytes data
                   :address addr
                   :perms perms
                   :named name)))

(defun page-align (n)
  (+ #x1000 (logand n #xFFFFF000)))

(defun format-elf-segment (ph &key (align))
  (let* ((perms (expand-flags (elf:flags ph)))
         (addr (elf:vaddr ph))
         (size (elf:memsz ph)))
    (when align
      (setq size (page-align size)))
    (make-segment :addr addr
                  :size size
                  :perm perms)))

(defun get-loadable-elf-segments (elf-obj &key (align t))
  (mapcar (lambda (s) (format-elf-segment s :align align))
          (remove-if-not
           (lambda (x)
             (eq :LOAD (elf:type x)))
           (elf:program-table elf-obj))))
