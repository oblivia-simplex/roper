;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Interface to the Unicorn Emulation Libary (written in C)         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(in-package :unicorn)

(define-foreign-library libunicorn
    (:unix (:or "libunicorn.so.1" "libunicorn.so"))
  (t (:default "libunicorn")))

(use-foreign-library libunicorn)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Some Constants for Mode and Arch ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defcenum uc-arch
  (:ARM 1)
  (:ARM64 2)
  (:MIPS 3)
  (:X86 4)
  (:PPC 5)
  (:SPARC 6)
  (:M86K 7)
  (:MAX 8))

(defcenum uc-mode
  (:LITTLE-ENDIAN 0)  ;; little-endian mode (default mode)
  (:BIG-ENDIAN #.(ash 1 30))  ;; big-endian mode
  ;; arm / arm64
  (:ARM 0)  ;; ARM mode
  (:THUMB #.(ash 1 4))  ;; THUMB mode (including Thumb-2)
  (:MCLASS #.(ash 1 5))  ;; ARM's Cortex-M series (currently unsupported)
  (:V8 #.(ash 1 6))  ;; ARMv8 A32 encodings for ARM (currently unsupported)
    ;; mips
  (:MICRO #.(ash 1 4))  ;; MicroMips mode (currently unsupported)
  (:MIPS3 #.(ash 1 5))  ;; Mips III ISA (currently unsupported)
  (:MIPS32R6 #.(ash 1 6))  ;; Mips32r6 ISA (currently unsupported)
  (:MIPS32 #.(ash 1 2))  ;; Mips32 ISA
  (:MIPS64 #.(ash 1 3))  ;; Mips64 ISA
      ;; x86 / x64
  (:16BIT #.(ash 1 1))  ;; 16-bit mode
  (:32BIT #.(ash 1 2))  ;; 32-bit mode
  (:64BIT #.(ash 1 3))  ;; 64-bit mode
      ;; ppc
  (:PPC32 #.(ash 1 2))  ;; 32-bit mode (currently unsupported)
  (:PPC64 #.(ash 1 3))  ;; 64-bit mode (currently unsupported)
  (:QPX #.(ash 1 4))  ;; Quad Processing eXtensions mode (currently unsupported)
      ;; sparc
  (:SPARC32 #.(ash 1 2))  ;; 32-bit mode
  (:SPARC64 #.(ash 1 3))  ;; 64-bit mode
  (:V9 #.(ash 1 4)))  ;; SparcV9 mode (currently unsupported)


(defcenum uc-err
  :OK  ;; No error: everything was fine
  :NOMEM  ;; Out-Of-Memory error: uc_open(), uc_emulate()
  :ARCH  ;; Unsupported architecture: uc_open()
  :HANDLE  ;; Invalid handle
  :MODE  ;; Invalid/unsupported mode: uc_open()
  :VERSION  ;; Unsupported version (bindings)
  :READ-UNMAPPED  ;; Quit emulation due to READ on unmapped memory: uc_emu_start()
  :WRITE-UNMAPPED  ;; Quit emulation due to WRITE on unmapped memory: uc_emu_start()
  :FETCH-UNMAPPED  ;; Quit emulation due to FETCH on unmapped memory: uc_emu_start()
  :HOOK  ;; Invalid hook type: uc_hook_add()
  :INSN-INVALID  ;; Quit emulation due to invalid instruction: uc_emu_start()
  :MAP  ;; Invalid memory mapping: uc_mem_map()
  :WRITE-PROT  ;; Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
  :READ-PROT  ;; Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
  :FETCH-PROT  ;; Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
  :ARG  ;; Inavalid argument provided to uc_xxx function (See specific function API)
  :READ-UNALIGNED  ;; Unaligned read
  :WRITE-UNALIGNED  ;; Unaligned write
  :FETCH-UNALIGNED  ;; Unaligned fetch
  :HOOK-EXIST  ;; hook for this event already existed
  :RESOURCE   ;; Insufficient resource: uc_emu_start()
  :EXCEPTION) ;; Unhandled CPU exception



(defcenum uc-mem-type
  (:READ 16)  ;; Memory is read from
  :WRITE   ;; Memory is written to
  :FETCH   ;; Memory is fetched
  :READ-UNMAPPED   ;; Unmapped memory is read from
  :WRITE-UNMAPPED   ;; Unmapped memory is written to
  :FETCH-UNMAPPED   ;; Unmapped memory is fetched
  :WRITE-PROT   ;; Write to write protected, but mapped, memory
  :READ-PROT   ;; Read from read protected, but mapped, memory
  :FETCH-PROT   ;; Fetch from non-executable, but mapped, memory
  :READ-AFTER   ;; Memory is read from (successful access)
  )

(defcstruct uc-mem-region
  (begin :uint64)  ;; begin address of the region (inclusive)
  (end   :uint64)  ;; end address of the region (inclusive)
  (perms :uint32)) ;; memory permissions of the region


(defcenum uc-query-type
  ;; Dynamically query current hardware mode.
  (:MODE 1)
  :PAGE-SIZE)

(defcenum uc-prot
   (:NONE 0)
   (:READ 1)
   (:WRITE 2)
   (:EXEC 4)
   (:ALL 7))

(defun permflags (perms)
  (reduce #'logior
          perms
          :initial-value 0
          :key (lambda (x)
                 (foreign-enum-value 'uc-prot x))))
(defctype unicorn-engine :pointer)

(defparameter +reg-ids+
  (list
   (list :arm (list '(0 . 66)
                    '(1 . 67)
                    '(2 . 68)
                    '(3 . 69)
                    '(4 . 70)
                    '(5 . 71)
                    '(6 . 72)
                    '(7 . 73)
                    '(8 . 74)
                    '(9 . 75)
                    '(10 . 76)
                    '(11 . 77)
                    '(12 . 78)
                    '(13 . 12)
                    '(14 . 10)
                    '(15 . 11)))))

(defun %reg-keyword (n)
  (intern (format nil "R~D" n) :keyword))

(defun %regn->regid (n &key (arch :arm))
  (cdr (assoc n (cadr (assoc arch +reg-ids+)))))


(defun range (lo hi)
  (loop for i from lo to (1- hi) collect i))

;;;;;;;;;;;;;;;;;;;;;;;;;
;; Functions
;;;;;;;;;;;;;;;;;;;;;;;
(defcfun "uc_arch_supported" :bool (arch uc-arch))

;; here's an important one. will need a wrapper.
(defcfun ("uc_open" %uc-open) uc-err
  (unicorn-arch uc-arch)
  (unicorn-mode uc-mode)
  (uc (:pointer unicorn-engine)))
;; how big should the pointer be? it's a pointer to a pointer to a
;; uc_struct...
(defparameter *pointer-size* 8)
(defun uc-open (unicorn-arch unicorn-mode)
  "Takes unicorn arch and mode parameters, and returns an engine"
  (handler-case
      (with-foreign-pointer (uc *pointer-size*)
        (%uc-open unicorn-arch unicorn-mode uc)
        (mem-ref uc :pointer))
    (error (ex)
      (format t "Error initializing unicorn engine:~%~T-> ~A~%" ex))))


(defcfun ("uc_close" %uc-close) uc-err
  (uc :pointer))

(defun uc-close (uc)
  (handler-case (%uc-close uc)
    (error (ex)
      (format t "Warning: unable to close uc:~%~T-> ~A~%" ex))))

(defcfun ("uc_version" %uc-version) :uint
  (major (:pointer :uint))
  (minor (:pointer :uint)))

(defun uc-version ()
  (with-foreign-pointer (major 8)
    (with-foreign-pointer (minor 8)
      (%uc-version major minor)
      (values (mem-ref major :uint)
              (mem-ref minor :uint)))))

(defcfun ("uc_query" %uc-query) uc-err
  (engine unicorn-engine)
  (query-type :uint)
  (result :pointer))

(defun uc-query (engine query-type)
  (with-foreign-pointer (result 8)
    (%uc-query engine
               (foreign-enum-value 'uc-query-type query-type)
               result)
    (case query-type
      ((:mode) (foreign-enum-keyword 'uc-mode
                                     (mem-ref result :uint)))
      ((:page-size) (mem-ref result :uint))
      (:otherwise result))))

(defun mode-eq (mode1 mode2)
  (= (foreign-enum-value 'uc-mode mode1)
     (foreign-enum-value 'uc-mode mode2)))

(defun in-mode-p (engine uc-mode)
  (mode-eq (uc-query engine :mode) uc-mode))

(defcfun ("uc_reg_write" %uc-reg-write) uc-err
  (uc-engine unicorn-engine)
  (regid :uint)
  (value :pointer))


(defun uc-reg-write (engine register value &key (type :uint64))
  (with-foreign-pointer (valptr 8)
    (setf (mem-ref valptr type) (convert-to-foreign value type))
    (%uc-reg-write engine (%regn->regid register) valptr)))

(defcfun ("uc_reg_read" %uc-reg-read) uc-err
  (uc-engine unicorn-engine)
  (regid :uint)
  (value :pointer))

(defun uc-reg-read (engine register &key (type :uint64))
  "Returns the register contents as the first value, and the
error code as the second."
  (with-foreign-pointer (valptr 8)
    (let ((err (%uc-reg-read engine (%regn->regid register) valptr)))
      (values (mem-ref valptr type) err))))

(defun uc-reg-write-batch (engine registers values
                           &key (type :uint64))
  (mapc (lambda (r v) (uc-reg-write engine r v :type type))
        registers values))

(defun uc-reg-read-batch (engine registers &key (type :uint64))
  (mapcar (lambda (r) (uc-reg-read engine r :type type)) registers))

(defcfun ("uc_mem_write" %uc-mem-write) uc-err
  (uc-engine unicorn-engine)
  (address :uint64)
  (bytes (:pointer :uint8))
  (size :uint))


(defun bytes->pointer (bytes)
  (foreign-alloc :uint8
                 :initial-contents bytes))

(defun pointer->bytes (pointer size)
  (let ((buffer (make-array size :element-type '(unsigned-byte 8))))
    (loop for i below size
          do (setf (aref buffer i)
                   (mem-aref pointer :uint8 i)))
    buffer))

(defun uc-mem-write (engine address bytes)
  (unwind-protect
       (let* ((length (length bytes))
              (ptr (bytes->pointer bytes))
              (ret (%uc-mem-write engine
                                  (convert-to-foreign address :uint64)
                                  ptr
                                  length)))
         (foreign-free ptr)
         ret)))

(defcfun ("uc_mem_read" %uc-mem-read) uc-err
  (uc-engine unicorn-engine)
  (address :uint64)
  (bytes :pointer)
  (size :uint))

(defun uc-mem-read (engine address size)
  (with-foreign-pointer (buffer size)
    (%uc-mem-read engine address buffer size)
    (pointer->bytes buffer size)))

(defcfun ("uc_mem_map" %uc-mem-map) uc-err
  (uc-engine unicorn-engine)
  (address :uint64)
  (size :uint)
  (perms :uint32))

(defun uc-mem-map (engine address size perms)
  (%uc-mem-map engine address size (permflags perms)))

(defcfun ("uc_emu_start" %uc-emu-start) uc-err
  (uc-engine unicorn-engine)
  (begin :uint64)
  (until :uint64)
  (timeout :uint64)
  (count :uint64))

(defun uc-emu-start (engine begin &key
                                    (until 0)
                                    (timeout 0)
                                    (count 0))
  (%uc-emu-start engine begin until timeout count))

(defparameter ~test-code~
  #(#x37 #x00 #xa0 #xe3   ;; mov r0, #x037
    #x03 #x10 #x42 #xe0)) ;; sub r1, r2, r3


