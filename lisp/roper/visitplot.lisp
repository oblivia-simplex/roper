;;; lazily dumping all i need right here.
(defpackage :visitplot
  (:use :common-lisp))
(in-package :visitplot )

(ql:quickload :cl-ppcre)
(ql:quickload :elf)

(deftype bytes () '(vector (unsigned-byte 8)))

(defun bytes->dword (vec &key (offset 0) (width 4) (endian :little))
  ;; not implemented for big-endian yet
  (if (eq endian :big)
      (error "NOT IMPLEMENTED FOR BIG ENDIAN")
      (let ((dword 0))
        (loop for i below width
              while (< (+ i offset) (length vec)) do
                (incf dword
                      (ash (elt vec (+ i offset)) (* i 8))))
        dword)))

(defun word->bytes (word &key (endian :little) (width 4))
  (let ((res (mapcar (lambda (i) (ldb (byte 8 (* i 8)) word))
                     (loop for i below width collect i))))
    (if (eq endian :big) (reverse res) res)))

(defun bytes->dwords (bytes &key (width 4) (endian :little))
  (let* ((len (length bytes))
         (ext (mod len width)))
    (if (zerop len)
        '()
        (let ((bytes
                (if (zerop (mod len width))
                    bytes
                    (let ((zeros (loop repeat (- width ext) collect 0))
                          (stub (subseq bytes (- len ext))))
                      (concatenate 'vector
                                   (subseq bytes 0 (- len ext))
                                   (if (eq endian :little) stub zeros)
                                   (if (eq endian :little) zeros stub))))))
          (loop for i below (- (length bytes) 1) by width
                collect
                (bytes->dword bytes :offset i :width width))))))

(defun dwords->bytes (dwords &key (endian :little))
  (let ((bytes)
        (lo (if (eq endian :little) 0 3))
        (hi (if (eq endian :little) 3 0))
        (step (if (eq endian :little) #'1+ #'1-)))
    (loop for word in dwords do
      (let ((i lo))
        (loop while (/= i (funcall step hi)) do;; generalize
                                               (push (ldb (byte 8 (* i 8)) word) bytes)
                                               (setq i (funcall step i)))))
    (reverse bytes)))

 
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

(export 'bytes-at)
(defun bytes-at (section address &optional (width 4))
  (when (<= (sec-addr section)
                 address
                 (1- (+ (sec-addr section)
                        (length (sec-data section)))))
    (subseq (sec-data section)
            address
            (+ address width))))

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

(defvar +red+ 0)
(defvar +green+ 1)
(defvar +blue+ 2)



(defun asciip (b)
  (or (< #x07 b #x0E) (< #x1F b #x80)))

;;;;; for parsing roper logs


(defun wordalign (w)
  (ash (ash w -2) 2))

(defun %parse-visited-log (path)
  (let ((state :init)
        (problem nil)
        (*read-base* 16)
        (elf-path nil)
        (visit-maps (make-hash-table :test #'equalp)))
    (labels ((enter (str item)
               (push item (gethash str visit-maps)))
             (scan (line)
               (case state
                 ((:init)
                  (multiple-value-bind (_ p)
                      (cl-ppcre:scan-to-strings
                       "^=== VISIT MAP FOR BINARY ([^\]]+) ==="
                       line)
                    (declare (ignore _))
                    (if p
                        (setq elf-path (elt p 0))
                        (setq state :begin))))
                 ((:begin)
                  (multiple-value-bind (txt p)
                      (cl-ppcre:scan-to-strings
                       "^--- BEGIN VISIT MAP FOR PROBLEM ([0-9a-f.]+)"
                       line)
                    (if txt
                        (progn
                          (setq problem (elt p 0))
                          (setq state :addr))
                        nil)))
                 ((:addr)
                  (multiple-value-bind (_ a)
                      (cl-ppcre:scan-to-strings
                       "^([0-9a-f]+) (stray)?|^--- (END) VISIT MAP FOR PROBLEM"
                       line)
                    (declare (ignore _))
                    (if a
                        (let ((addr  (elt a 0))
                              (stray (elt a 1))
                              (end   (elt a 2)))
                          (if addr (wordalign (setq addr (read-from-string addr))))
                          (if end
                              (progn (setq state :begin)
                                     (setq problem nil))
                              (if addr
                                  (enter problem (list addr stray))
                                  nil))
                          nil)))))))
             (with-open-file (s path :direction :input)
               (loop for row = (read-line s nil nil)
                     while row do
                       (scan row))))
    (loop for k being the hash-keys of visit-maps do
      (setf (gethash k visit-maps)
            (reverse (gethash k visit-maps))))
    (values visit-maps elf-path)))

(defun get-text (elf-path)
  (find :.text
        (get-elf-sections (elf:read-elf elf-path))
        :key #'sec-name))

(defun parse-visited-log (path)
  (multiple-value-bind (visited-log elf-path)
      (%parse-visited-log path)
    (values
     visited-log
     (get-text elf-path))))

(defun bytes-to-pixels (bytes color) ;; +red+ +green+ or +blue+
  (apply #'concatenate 'list
               (mapcar (lambda (b)
                         (let ((pixel (list 0 0 0)))
                           (setf (elt pixel color) b)
                           pixel))
                       bytes)))

(defun word->pixels (word color &key (width 4))
  (bytes-to-pixels (coerce (word->bytes word
                                        :endian :little
                                        :width width)
                           'list) color))

;; unvisited: +blue+
;; visited: +green+
;; visited and stray: +red+

(defun colormap (section visit-maps &key (width 4))
  (loop for k being the hash-keys of visit-maps
        collect
        (let* ((pixelrow (make-array (* 3 (length (sec-data section)))
                                     :element-type '(unsigned-byte 8)))
               (offset 0)
               (addr (sec-addr section))
               (visits (gethash k visit-maps))
               (nextvis (pop visits)))
           (loop for dword across (sec-words section)
                 do
                 (let ((color +blue+))
                   (when (and nextvis (= addr (car nextvis))
                          (if (cadr nextvis) ;; if stray
                              (setq color +red+)
                              (setq color +green+))
                          (setq nextvis (pop visits))))
                   (incf addr width)
                   (mapc (lambda (x)
                           (setf (aref pixelrow offset) x)
                           (incf offset))
                         (dword->pixels dword color))))
          pixelrow)))

(defun maxheat (heatmap-alist)
  (reduce #'max (mapcar #'cdr heatmap-alist)))

(defun read-heatmap (path)
  (let ((hm (with-open-file (s path)
              (read s))))
    (mapc (lambda (x)
            (setf (car x)
                  (wordalign (car x))))
          hm)
    hm))

;;NB the chains appear to be visiting some addresses lower than text!

(defun heatmap->colormap (section heatmap-alist &key (width 4))
  (let ((m (maxheat heatmap-alist)))
    (assert (> m 0))
    (labels ((calc-heat (h)
               (floor (* #xFF (/ h m)))))
      (let ((pixelrow (make-array (* 3 (length (sec-data section)))
                                  :element-type '(unsigned-byte 8)))
            (offset 0)
            (addr (sec-addr section)))
        ;; kludge, but figure out why sub-text addrs are being visited.
        ;; did i map other executable memory? investigate
        (loop for word across (sec-words section) do
          (let ((pixels (word->pixels word +blue+ ))
                (nextheat (assoc addr heatmap-alist)))
            (when nextheat ;; optimise with hashtable
              (setf pixels
                    (mapcar #'logior
                            pixels
                            (loop for i below width
                                  append
                                  (let ((p (list 0 0 0)))
                                    (setf (elt p +red+)
                                          (calc-heat (cdr nextheat)))
                                    p))))
              (format t "heat> ~S~%" pixels))
            (incf addr width)
            (mapc (lambda (x)
                    (setf (aref pixelrow offset) x)
                    (incf offset))
                  pixels)))
        pixelrow))))

(defun %superimpose (a b)
  (map 'bytes #'logior a b))

(defun superimpose (colormap)
  (reduce #'%superimpose colormap))

(defun %%superimpose (colormap)
  (apply #'map 'bytes (lambda (&rest xs)
                (reduce #'logior xs))
         colormap))



(defun visited->colormap (path)
  (multiple-value-bind (visit-maps textsec)
      (parse-visited-log path)
    (let* ((full-cm (colormap textsec visit-maps))
           (dedupe-cm (remove-duplicates full-cm :test #'equalp)))
      dedupe-cm)))


(defun make-ppm-header (height width)
  (mapcar #'char-code
          (coerce (format nil "P6~%~D ~D~%255~%" width height) 'list)))

(defun paint-canvas (colormap-row ppm-path)
  (let* ((pixelcount (/ (length colormap-row) 3))
        ; (dim (ceiling (sqrt pixelcount)))
        ; (height dim)
         (%width (ceiling (sqrt pixelcount)))
         (width (+ %width (mod %width 4)))
         (height (ceiling (/ pixelcount width)))

         (pad (loop for i below (* 3 (- (* height width) pixelcount))
                    collect 0)))
    (format t "Using zero pad of ~D bytes..." (length pad))
    (with-open-file (stream ppm-path :if-exists :supersede
                                     :element-type '(unsigned-byte 8)
                                     :direction :output)
      (let ((header (make-ppm-header height width)))
        (write-sequence header stream)
        (write-sequence colormap-row stream)
        (write-sequence pad stream)))))

(defun colormap->canvases (colormap dirname)
    (ensure-directories-exist dirname)
    (loop for colormap-row in colormap
          for i from 0 do
            (let ((ppm-path (format nil "~A/visitmap_~D.ppm" dirname i)))
              (paint-canvas colormap-row ppm-path))))

(defun visited->supercanvas (log-path ppm-path)
  (paint-canvas (superimpose (visited->colormap log-path))
                ppm-path))

(defun visited->montage (path dirname)
  (let* ((colormap (visited->colormap path))
         (dim (ceiling (sqrt (length colormap))))
         (cmd (format nil "montage ~A/*.ppm -geometry +~D+~D ~A/montage.png"
                      dirname dim dim dirname)))
    (colormap->canvases colormap dirname)
    (asdf:run-shell-command cmd)))

;; NB: to reduce memory footprint, do a binary merge superimpose on
;; total list of colormaps
(defun superimpose-directory (dir)
  (let ((colormap ())
        (dir (directory
              (make-pathname :directory dir
                             :name :wild
                             :type :wild))))
    (format t "dir: ~S" dir)
    (loop for log in dir do
      (push (superimpose (visited->colormap log)) colormap))
    colormap))


(defun heatmap->canvas (elf-path heatmap-path ppm-path)
  (let ((colormap-row (heatmap->colormap (get-text elf-path)
                                         (read-heatmap heatmap-path))))
    (paint-canvas colormap-row ppm-path)))
