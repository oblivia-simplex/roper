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

(defun merge-flags (flags &key (enum-type 'uc-prot))
  (reduce #'logior
          flags
          :initial-value 0
          :key (lambda (x)
                 (foreign-enum-value enum-type x))))

(defctype unicorn-engine :pointer)
(defctype size :uint)


(defcenum uc-hook-type
  ;; Hook all interrupt/syscall events
  (:INTR #.(ash 1 0))
  ;; Hook a particular instruction - only a very small subset of instructions supported here
  (:INSN #.(ash 1 1))
  ;; Hook a range of code
  (:CODE #.(ash 1 2))
  ;; Hook basic blocks
  (:BLOCK #.(ash 1 3))
  ;; Hook for memory read on unmapped memory
  (:MEM_READ_UNMAPPED #.(ash 1 4))
  ;; Hook for invalid memory write events
  (:MEM_WRITE_UNMAPPED #.(ash 1 5))
  ;; Hook for invalid memory fetch for execution events
  (:MEM_FETCH_UNMAPPED #.(ash 1 6))
  ;; Hook for memory read on read-protected memory
  (:MEM_READ_PROT #.(ash 1 7))
  ;; Hook for memory write on write-protected memory
  (:MEM_WRITE_PROT #.(ash 1 8))
  ;; Hook for memory fetch on non-executable memory
  (:MEM_FETCH_PROT #.(ash 1 9))
  ;; Hook memory read events.
  (:MEM_READ #.(ash 1 10))
  ;; Hook memory write events.
  (:MEM_WRITE #.(ash 1 11))
  ;; Hook memory fetch for execution events
  (:MEM_FETCH #.(ash 1 12))
  ;; Hook memory read events, but only successful access.
  ;; The callback will be triggered after successful read.
  (:MEM_READ_AFTER #.(ash 1 13)))

(defparameter +reg-ids+
  (list
   (list :x86 (list '(:INVALID . 0)
                    '(:AH . 1)
                    '(:AL . 2)
                    '(:AX . 3)
                    '(:BH . 4)
                    '(:BL . 5)
                    '(:BP . 6)
                    '(:BPL . 7)
                    '(:BX . 8)
                    '(:CH . 9)
                    '(:CL . 10)
                    '(:CS . 11)
                    '(:CX . 12)
                    '(:DH . 13)
                    '(:DI . 14)
                    '(:DIL . 15)
                    '(:DL . 16)
                    '(:DS . 17)
                    '(:DX . 18)
                    '(:EAX . 19)
                    '(:EBP . 20)
                    '(:EBX . 21)
                    '(:ECX . 22)
                    '(:EDI . 23)
                    '(:EDX . 24)
                    '(:EFLAGS . 25)
                    '(:EIP . 26)
                    '(:EIZ . 27)
                    '(:ES . 28)
                    '(:ESI . 29)
                    '(:ESP . 30)
                    '(:FPSW . 31)
                    '(:FS . 32)
                    '(:GS . 33)
                    '(:IP . 34)
                    '(:RAX . 35)
                    '(:RBP . 36)
                    '(:RBX . 37)
                    '(:RCX . 38)
                    '(:RDI . 39)
                    '(:RDX . 40)
                    '(:RIP . 41)
                    '(:RIZ . 42)
                    '(:RSI . 43)
                    '(:RSP . 44)
                    '(:SI . 45)
                    '(:SIL . 46)
                    '(:SP . 47)
                    '(:SPL . 48)
                    '(:SS . 49)
                    '(:CR0 . 50)
                    '(:CR1 . 51)
                    '(:CR2 . 52)
                    '(:CR3 . 53)
                    '(:CR4 . 54)
                    '(:CR5 . 55)
                    '(:CR6 . 56)
                    '(:CR7 . 57)
                    '(:CR8 . 58)
                    '(:CR9 . 59)
                    '(:CR10 . 60)
                    '(:CR11 . 61)
                    '(:CR12 . 62)
                    '(:CR13 . 63)
                    '(:CR14 . 64)
                    '(:CR15 . 65)
                    '(:DR0 . 66)
                    '(:DR1 . 67)
                    '(:DR2 . 68)
                    '(:DR3 . 69)
                    '(:DR4 . 70)
                    '(:DR5 . 71)
                    '(:DR6 . 72)
                    '(:DR7 . 73)
                    '(:DR8 . 74)
                    '(:DR9 . 75)
                    '(:DR10 . 76)
                    '(:DR11 . 77)
                    '(:DR12 . 78)
                    '(:DR13 . 79)
                    '(:DR14 . 80)
                    '(:DR15 . 81)
                    '(:FP0 . 82)
                    '(:FP1 . 83)
                    '(:FP2 . 84)
                    '(:FP3 . 85)
                    '(:FP4 . 86)
                    '(:FP5 . 87)
                    '(:FP6 . 88)
                    '(:FP7 . 89)
                    '(:K0 . 90)
                    '(:K1 . 91)
                    '(:K2 . 92)
                    '(:K3 . 93)
                    '(:K4 . 94)
                    '(:K5 . 95)
                    '(:K6 . 96)
                    '(:K7 . 97)
                    '(:MM0 . 98)
                    '(:MM1 . 99)
                    '(:MM2 . 100)
                    '(:MM3 . 101)
                    '(:MM4 . 102)
                    '(:MM5 . 103)
                    '(:MM6 . 104)
                    '(:MM7 . 105)
                    '(:R8 . 106)
                    '(:R9 . 107)
                    '(:R10 . 108)
                    '(:R11 . 109)
                    '(:R12 . 110)
                    '(:R13 . 111)
                    '(:R14 . 112)
                    '(:R15 . 113)
                    '(:ST0 . 114)
                    '(:ST1 . 115)
                    '(:ST2 . 116)
                    '(:ST3 . 117)
                    '(:ST4 . 118)
                    '(:ST5 . 119)
                    '(:ST6 . 120)
                    '(:ST7 . 121)
                    '(:XMM0 . 122)
                    '(:XMM1 . 123)
                    '(:XMM2 . 124)
                    '(:XMM3 . 125)
                    '(:XMM4 . 126)
                    '(:XMM5 . 127)
                    '(:XMM6 . 128)
                    '(:XMM7 . 129)
                    '(:XMM8 . 130)
                    '(:XMM9 . 131)
                    '(:XMM10 . 132)
                    '(:XMM11 . 133)
                    '(:XMM12 . 134)
                    '(:XMM13 . 135)
                    '(:XMM14 . 136)
                    '(:XMM15 . 137)
                    '(:XMM16 . 138)
                    '(:XMM17 . 139)
                    '(:XMM18 . 140)
                    '(:XMM19 . 141)
                    '(:XMM20 . 142)
                    '(:XMM21 . 143)
                    '(:XMM22 . 144)
                    '(:XMM23 . 145)
                    '(:XMM24 . 146)
                    '(:XMM25 . 147)
                    '(:XMM26 . 148)
                    '(:XMM27 . 149)
                    '(:XMM28 . 150)
                    '(:XMM29 . 151)
                    '(:XMM30 . 152)
                    '(:XMM31 . 153)
                    '(:YMM0 . 154)
                    '(:YMM1 . 155)
                    '(:YMM2 . 156)
                    '(:YMM3 . 157)
                    '(:YMM4 . 158)
                    '(:YMM5 . 159)
                    '(:YMM6 . 160)
                    '(:YMM7 . 161)
                    '(:YMM8 . 162)
                    '(:YMM9 . 163)
                    '(:YMM10 . 164)
                    '(:YMM11 . 165)
                    '(:YMM12 . 166)
                    '(:YMM13 . 167)
                    '(:YMM14 . 168)
                    '(:YMM15 . 169)
                    '(:YMM16 . 170)
                    '(:YMM17 . 171)
                    '(:YMM18 . 172)
                    '(:YMM19 . 173)
                    '(:YMM20 . 174)
                    '(:YMM21 . 175)
                    '(:YMM22 . 176)
                    '(:YMM23 . 177)
                    '(:YMM24 . 178)
                    '(:YMM25 . 179)
                    '(:YMM26 . 180)
                    '(:YMM27 . 181)
                    '(:YMM28 . 182)
                    '(:YMM29 . 183)
                    '(:YMM30 . 184)
                    '(:YMM31 . 185)
                    '(:ZMM0 . 186)
                    '(:ZMM1 . 187)
                    '(:ZMM2 . 188)
                    '(:ZMM3 . 189)
                    '(:ZMM4 . 190)
                    '(:ZMM5 . 191)
                    '(:ZMM6 . 192)
                    '(:ZMM7 . 193)
                    '(:ZMM8 . 194)
                    '(:ZMM9 . 195)
                    '(:ZMM10 . 196)
                    '(:ZMM11 . 197)
                    '(:ZMM12 . 198)
                    '(:ZMM13 . 199)
                    '(:ZMM14 . 200)
                    '(:ZMM15 . 201)
                    '(:ZMM16 . 202)
                    '(:ZMM17 . 203)
                    '(:ZMM18 . 204)
                    '(:ZMM19 . 205)
                    '(:ZMM20 . 206)
                    '(:ZMM21 . 207)
                    '(:ZMM22 . 208)
                    '(:ZMM23 . 209)
                    '(:ZMM24 . 210)
                    '(:ZMM25 . 211)
                    '(:ZMM26 . 212)
                    '(:ZMM27 . 213)
                    '(:ZMM28 . 214)
                    '(:ZMM29 . 215)
                    '(:ZMM30 . 216)
                    '(:ZMM31 . 217)
                    '(:R8B . 218)
                    '(:R9B . 219)
                    '(:R10B . 220)
                    '(:R11B . 221)
                    '(:R12B . 222)
                    '(:R13B . 223)
                    '(:R14B . 224)
                    '(:R15B . 225)
                    '(:R8D . 226)
                    '(:R9D . 227)
                    '(:R10D . 228)
                    '(:R11D . 229)
                    '(:R12D . 230)
                    '(:R13D . 231)
                    '(:R14D . 232)
                    '(:R15D . 233)
                    '(:R8W . 234)
                    '(:R9W . 235)
                    '(:R10W . 236)
                    '(:R11W . 237)
                    '(:R12W . 238)
                    '(:R13W . 239)
                    '(:R14W . 240)
                    '(:R15W . 241)
                    '(:IDTR . 242)
                    '(:GDTR . 243)
                    '(:LDTR . 244)
                    '(:TR . 245)
                    '(:FPCW . 246)
                    '(:FPTAG . 247)
                    '(:MSR . 248)
                    '(:ENDING . 249)))
  (list :arm (list '(0 . 66)  '(:r0 . 66)
                   '(1 . 67)  '(:r1 . 67)
                   '(2 . 68)  '(:r2 . 68)
                   '(3 . 69)  '(:r3 . 69)
                   '(4 . 70)  '(:r4 . 70)
                   '(5 . 71)  '(:r5 . 71)
                   '(6 . 72)  '(:r6 . 72)
                   '(7 . 73)  '(:r7 . 73)
                   '(8 . 74)  '(:r8 . 74)
                   '(9 . 75)  '(:r9 . 75)
                   '(10 . 76)  '(:r10 . 76)
                   '(11 . 77)  '(:r11 . 77)
                   '(12 . 78)  '(:r12 . 78)
                   '(13 . 12)  '(:r13 . 12) '(:sp . 12)
                   '(14 . 10)  '(:r14 . 10) '(:lr . 10)
                   '(15 . 11)  '(:r15 . 11) '(:pc . 11)))))

(defun %reg-keyword (n)
  (intern (format nil "R~D" n) :keyword))

(defun %reg->regid (k &key (arch :arm))
  (cdr (assoc k (cadr (assoc arch +reg-ids+)))))

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


(defun uc-reg-write (engine register value &key
                                             (type :uint64)
                                             (arch :arm))
  (with-foreign-pointer (valptr 8)
    (setf (mem-ref valptr type) (convert-to-foreign value type))
    (%uc-reg-write engine (%reg->regid register :arch arch) valptr)))

(defcfun ("uc_reg_read" %uc-reg-read) uc-err
  (uc-engine unicorn-engine)
  (regid :uint)
  (value :pointer))

(defun uc-reg-read (engine register &key (type :uint64) (arch :arm))
  "Returns the register contents as the first value, and the
error code as the second."
  (with-foreign-pointer (valptr 8)
    (let ((err (%uc-reg-read engine (%reg->regid register :arch arch)
                             valptr)))
      (values (mem-ref valptr type) err))))

(defun uc-reg-write-batch (engine registers values
                           &key (type :uint64) (arch :arm))
  (mapc (lambda (r v) (uc-reg-write engine r v :type type :arch arch))
        registers values))

(defun uc-reg-read-batch (engine registers
                          &key (type :uint64) (arch :arm))
  (mapcar (lambda (r) (uc-reg-read engine r :type type :arch arch))
          registers))

(defcfun ("uc_mem_write" %uc-mem-write) uc-err
  (uc-engine unicorn-engine)
  (address :uint64)
  (bytes (:pointer :uint8))
  (size size))


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
  (size size))

(defun uc-mem-read (engine address size)
  (with-foreign-pointer (buffer size)
    (%uc-mem-read engine address buffer size)
    (pointer->bytes buffer size)))

(defcfun ("uc_mem_map" %uc-mem-map) uc-err
  (uc-engine unicorn-engine)
  (address :uint64)
  (size size)
  (perms :uint32))

(defun uc-mem-map (engine address size perms)
  (%uc-mem-map engine address size
               (merge-flags perms :enum-type 'uc-prot)))

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


(defcfun ("uc_hook_add" %uc-hook-add) uc-err
  (uc-engine unicorn-engine)
  (hook-handle :pointer) ;; hook handle used by uc_hook_del()
  (type :uint) ;; hook type enum
  (callback :pointer) ;; pointer to callback function
  (user-data :pointer) ;; passed to callback function in its last arg
  (begin :uint64) ;; start address of region hooked (incl.)
  (end :uint64) ;; end address of region hooked (incl.)
  ;; variable arguments, too... hm...
  ;; see the cffi tutorial for this. we might use foreign-funcall
  ;; instead of defcfun here.
  )

(defun fn->callback (fn)
  "Transforms a function into a callback pointer, for unicorn."
  (let ((cb-sym (gensym "CB")))
    (get-callback (defcallback cb-sym :void
                   ((uc unicorn-engine)
                    (address :uint64)
                    (size :uint32)
                    (user-data :pointer))
                 (funcall fn uc address size user-data)))))

(defun uc-hook-add (engine fn begin end
                    &key (hook-type :code)
                      (user-data (foreign-alloc :pointer)))
  (let* ((handle (foreign-alloc :pointer))
         (callback-ptr (fn->callback fn))
         (errcode (%uc-hook-add engine handle
                                (foreign-enum-value 'uc-hook-type
                                                    hook-type)
                                callback-ptr
                                user-data
                                begin
                                end)))
    (values handle errcode)))



;;;;;;;;;;;;;;;;;
;; For testing ;;
;;;;;;;;;;;;;;;;;
(defparameter ~test-code~
  #(#x37 #x00 #xa0 #xe3   ;; mov r0, #x037
    #x03 #x10 #x42 #xe0)) ;; sub r1, r2, r3

(defun code-hook-show-inst (uc address size user-data)
  (let ((inst (uc-mem-read uc address size))
        (regs (uc-reg-read-batch uc (range 0 16))))
    ;; a much better way to send data back!
    (incf (mem-aref user-data :uint64 0))
    (format t "[~4X] ~S => ~S~%"
            address inst regs)))

(defun set-up-tester ()
  (setf *uc* (uc-open :arm :arm))
  (uc-mem-map *uc* 0 #x1000 '(:read :write :exec))
  (uc-mem-write *uc* 0 ~test-code~)
  (uc-reg-write-batch *uc* (range 0 16) (loop repeat 16 collect 5)))
