(in-package :params)

(export '*tweakables*)
(defvar *tweakables* ())

(export 'tweakable-p)
(defun tweakable-p (sym)
  (let ((str (symbol-name sym)))
    (and (char= #\< (aref str 0)))
    (and (char= #\> (aref str (1- (length str)))))))

(defparameter <params-path>
  #P"/tmp/roper-params.lisp"
  "Path to lisp file setting tweakable parameters.")


(defparameter <elf-path>
  #P"/home/oblivia/Projects/roper/data/tomato-RT-AC3200-132-AIO-httpd"
  "Path to the ELF binary from which to extract gadgets.")

(defparameter <typed-ropush-minlens>
  '((:gadget 4) (:dword 4) (:int 4))
"The minimum quantity, for each ROPUSH type, of value to be used in initial creature generation.")

(defparameter <training-data-path>
 "/home/oblivia/Projects/roper/data/iris.data"
  "Path to the CSV training data file, if one is being used.")
    
(defparameter <max-emu-steps>
  #x10000
  "Upper bound on the number of steps that the Unicorn emulator will execute, for a given payload.")

(defparameter <cpu-arch>
  :ARM
  "The CPU architecture to target. Currently supported are ARM and (to a lesser extent) MIPS.")

(defparameter <word-size> 32
  "The word size, in bits, for the architecture and mode being used. This should probably be derived automatically. Don't fuss with it.")

(defparameter <cpu-mode>
  :ARM
  "The CPU mode to target. Architecture specific options.")

(defparameter <endian>
  :little
  "Endianness of the architecture.")

(defparameter <inregs>
  '(3 4 5)
  "List of integers indexing the input registers")

(defparameter <outregs>
  '(0 1 2)
  "List of integers indexing the output registers")

(defparameter <max-push-steps>
  1024
  "Maximum number of ROPUSH instructions to execute.")

;;; Now export muffed
(defun export-tweakable ()
  (let ((thispkg (find-package :params)))
    (setq *tweakables* ())
    (do-symbols (s :params)
      (when (and (equalp (symbol-package s) thispkg)
		 (tweakable-p s))
	(push s *tweakables*)
	(export s)))
    *tweakables*))

(export-tweakable)
