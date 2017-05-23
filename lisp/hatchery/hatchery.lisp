(in-package :hatchery)

(defun mem-map-seg (uc seg)
  (ok! (uc-mem-map uc
                   (segment-addr seg)
                   (segment-size seg)
                   (segment-perm seg))))

(defun mem-write-sec (uc sec)
  (ok! (uc-mem-write uc
                     (section-addr sec)
                     (section-data sec))))

(defun init-engine (arch mode elf-obj)
  (let* ((uc (uc-open arch mode))
         (segs  (merge-segments (get-loadable-elf-segments elf-obj :align t)))
         (secs (secs-in-segs (get-elf-sections elf-obj) segs)))
    (mapc (lambda (s) (mem-map-seg uc s)) segs)
    (mapc (lambda (s) (mem-write-sec uc s)) secs)
    (values uc secs segs)))

;; TODO: hatch-chain

(defvar +stop-addr+ #x00000000)
(defvar +max-steps+ #x10000)
(defvar +max-time+  #x10000000)


(defun hatch-chain (&key
                      (uc)
                      (chain)  ;; a chain struct/object
                      (input)  ;; list of fixnums
                      (inregs) ;; list of fixnums -- reg indexes
                      (outregs) ;;
                      (reset)
                      (stack-addr)
                      (stack-size)
                      (stack-ptr)) ;; boolean))
  (let* ((counter (foreign-alloc :uint64))
         (cb (fn->callback (lambda (uc addr size data)
                             (declare (ignore uc addr size data))
                             (incf (mem-ref data :uint64)))))
         (stack (chain-packed chain))
         (start (first-address chain))
         (cb-handles
           (loop for ret in (chain-rets chain)
                 collect (uc-hook-add uc ret ret :callback-ptr cb
                                                 :hook-type :code)))) ;; get first word from first clump
    (ok! (uc-reg-write-batch uc inregs input))
    (when reset
      (ok! (uc-mem-zero uc stack-addr stack-size)))
    (ok! (uc-mem-write uc stack-ptr stack))

    (let* ((error-code (uc-emu-start start
                                     :until +stop-addr+
                                     :timeout +max-time+
                                     :count +max-steps))
           (counted (mem-ref counter :uint64)))
      (loop for h in cb-handles do
        (ok! (uc-hook-del uc h))) ;; implement!
      (foreign-free counter)
      (foreign-free cb)
      (values (uc-reg-read-batch outregs)
              error-code
              counted))))

;; TODO:
;; - implement chain and clump structs, and related functions/methods
;; - uc-hook-remove
