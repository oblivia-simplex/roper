(in-package :frontend)
(use-package :params)
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; A pretty front-end
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(defparameter *argv*
  #+sbcl
  sb-ext:*posix-argv*
  #+ccl
  ccl:*command-line-argument-list*)

;(defun string->earmuff (string)
;  (let ((muffed (concatenate 'string "*" (string-upcase string) "*")))
;    (intern muffed)))

;(defun earmuff->string (symbol)
;  (let ((string (remove #\* (symbol-name symbol))))
;    string))

(defun anglesym->string (sym)
  (let ((name (symbol-name sym)))
    (if (tweakable-p sym)
	(subseq name 1 (1- (length name)))
	name)))

(defun param->posixopt (symbol)
  (concatenate 'string "--"
               (string-downcase
                (anglesym->string symbol))))

(defun print-params ()
  (loop
     for symbol in *params*
     for i from 0 to (length *params*) do
       (format t "[~d] ~A  ~S~%     ~A~%" i (param->posixopt symbol)
               (symbol-value symbol)
               (documentation symbol 'variable))))


(defun get-opt-arg (list key)
  (let ((anything-there (member key list :test #'equalp)))
    (when anything-there
      (cadr anything-there))))

(defun print-help ()
  (format t "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=~%")
  (format t "                                 ROPER~%")
  (format t "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=~%~%")
  (format t
"Many of the dynamic (global) parameters in ROPER can be set using
familiar POSIX-style command line argument syntax. Valid options and
the default values of the parameters they modify are printed below.
Note that quotation marks must be escaped for string arguments, but
keywords (prefixed by a colon) need no quotes.~%~%")
  (print-params)
  nil)

(defun parse-command-line-args ()
  (let ((args (cdr *argv*)))
    ;;    (FORMAT T "ARGV = ~S~%" args)
    (when (member (param->posixopt '<params-path>) args)
      (format t "READING PARAMETERS FROM ~A~%" <params-path>)
      (read-parameter-file
       (read-from-string
        (get-opt-arg args (param->posixopt '<params-path>)))))
                                                          
    (cond ((or (member "--help" args :test #'equalp)
               (member "-h" args :test #'equalp))
           (print-help))
          (t (hrule)
             (loop for param in *params* do
                  (let ((key (param->posixopt param)))
                    (when (member key args :test #'equalp)
                      ;; (FORMAT T "FOUND OPT: ~S = ~S~%"
                      ;; key (get-opt-arg args key))
                      (setf (symbol-value param)
                            (read-from-string (get-opt-arg args key)))
                      (format t "[+] SETTING ~A TO ~A...~%"
                              param (symbol-value param))))) T))))

    ;;           (format t "~S = ~S~%" param (symbol-value param))))))

(defun menu ()
    "The front end and user interface of the programme. Allows the user
to tweak a number of dynamically scoped, special variables, and then
launch setup and evolve."
  (flet ((validate (n)      
           (or (eq n :Q) 
               (and (numberp n)
                    (<= 0 n)
                    (< n (length *params*))))))    
    (let ((sel))
      (loop do
           (hrule)
           (print-params)
           (hrule)
           (loop do 
                (format t "~%ENTER NUMBER OF PARAMETER TO TWEAK, OR :Q TO PROCEED.~%")
                (princ "~ ")
;                (clear-input)
                (setf sel (read))
                (when (validate sel) (return)))
           (when (eq sel :Q) (return))
           (format t "~%YOU SELECTED ~D: ~A~%CURRENT VALUE: ~S~%     ~A~%~%"
                   sel
                   (elt *params* sel)
                   (symbol-value (elt *params* sel))
                   (documentation (elt *params* sel) 'variable))
           (format t "ENTER NEW VALUE (BE CAREFUL, AND MIND THE SYNTAX)~%~~ ")
           (setf (symbol-value (elt *params* sel)) (read))
           (format t "~A IS NOW SET TO ~A~%"
                   (elt *params* sel)
                   (symbol-value (elt *params* sel)))))))


(defun sanity-check ()
  "A place to prevent a few of the more disasterous parameter clashes
and eventually, sanitize the input."
  (when (or (eql *migration-size* 0) (eql *greedy-migration* 0))
    (setf *greedy-migration* nil))
  ;; (unless *sex*
  ;;   (setf *mutation-rate* 1))
  (when *debug*
    (setf *parallel* nil)
    (when (eq *selection-method* :lexicase)
      (format t "WARNING: *TRACK-GENEALOGY* CURRENTLY INCOMPATIBLE")
      (format t " WITH LEXICASE SELECTION.~%DISABLING.")
      (setf *track-genealogy* nil)
      (setf *case-storage* t))))

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


(defun read-parameter-file (param-path)
  (load param-path))



;; todo: write a generic csv datafile->hashtable loader, for
;; deployment on arbitrary datasets. 

;; it's not convenient, yet, to select the VM at runtime. this choice needs
;; to be made at compile time, for the time being. 



(defun save-parameters (&optional (param-path *last-params-path*))
  "Will append to existing file, allowing old settings to be retrieved if
accidentally clobbered."
  (with-open-file (stream param-path
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (format stream "~%~A~%~%" (timestring))
    (loop for param in *params* do
         (format stream "~S~%"
                 `(setf ,param ,(symbol-value param))))))

;;(defun save-island-ring (&key (filename "ISLAND-RING.SAV")
  ;;                          (bury-parents t)
  ;;                          (island-ring +ISLAND-RING+))
  ;; (let ((copy (island-ring-writeable-copy island-ring
  ;;                                         :bury-parents bury-parents)))
  ;;   (with-open-file (stream filename
  ;;                           :direction :output
  ;;                           :if-exists :supersede 
  ;;                           :if-does-not-exist :create)
  ;;     (setf *print-circle* nil)
  ;;     (format stream
  ;;             "~A~%;; +ISLAND-RING+ below: ~%~%~S~%)"
  ;;             (timestring)
  ;;             copy)
  ;;     (setf *print-circle* T))))

;; (defun island-ring-writeable-copy (island-ring &key (bury-parents t))
;;   (let ((copy (mapcar #'copy-structure (de-ring island-ring))))
;;     (loop for isle in copy do
;;          (when bury-parents
;;            (mapc #'bury-parents (island-deme isle))
;;            (mapc #'bury-parents (island-packs isle)))
;;          (setf (island-method isle) nil)
;;          (setf (island-lock isle) nil)
;;          (setf (island-logger isle) nil)
;;          (setf (island-coverage isle) nil))
;;     copy))

;; ;; ;; placeholders
;; ;; (defun tournement! ())
;; (defun roulette! ())
;; (defun greedy-roulette! ())
;; (defun lexicase! ())

;; (defun restore-island-ring (&key (filename "ISLAND-RING.SAV"))
;;   (let ((copy)
;;         (method-chooser))
;;     (format t "[-] RESTORING ISLAND-RING FROM ~A..." filename)
;;     (with-open-file (stream filename :direction :input
;;                             :if-does-not-exist nil)
;;       (and (setf copy (read stream))
;;            (format t "    ISLAND-RING SUCCESSFULLY RESTORED!")))
;;     (loop for isle in copy do
;;          (setf (island-logger isle) (make-logger))
;;          (setf (island-lock isle) (sb-thread:make-mutex
;;                                    :name (format nil "isle-~d-lock"
;;                                                  (island-id isle))))
;;          (setf (island-era isle) 0) ;; necessary to prevent certain bugs
;;          ;; but admittedly a bit of a kludge
;;          (if *case-storage* 
;;              (setf (island-coverage isle) (init-cases-covered
;;                                            *training-hashtable*)))
         
         ;; (setf method-chooser
         ;;       (if (island-packs isle)
         ;;                 *pack-selection-method*
         ;;                 *selection-method*))
         
         ;; (setf (island-method isle)
         ;;       (case method-chooser                        
         ;;         ((:tournement) #'tournement!)
         ;;         ((:roulette) #'roulette!)
         ;;         ((:greedy-roulette) #'greedy-roulette!)
         ;;         ((:lexicase) #'lexicase!)
;;          ;;         (otherwise (progn
;;          ;;                      (format t "WARNING: METHOD NAME NOT RECO")
;;                               (format t "GNIZED. USING #'TOURNEMENT!.~%")
;;                               #'tournement!)))))

;;     (setf +island-ring+ (circular copy))))


;; Note: it should be simple enough to generalize the ttt data processing
;; technique.
;; - scan the dataset
;; - count the possible values for each field, and if there are an equal
;;   number of possibilities for each field, say n, formalize the key as
;;   an m-digit base-n gray code integer.
;; - this may, in some cases, even work when there is a maximum number
;;   of possibilities per field. or if each field can have any of n
;;   values, when unconstrained by other fields (the mutual constraints,
;;   of course, are an impt aspect of the pattern that the algo's meant
;;   to detect). 

















