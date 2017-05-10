(in-package :junk-drawer)


(defun bytes->pointer (bytes)
  (foreign-alloc :uint8
                 :initial-contents bytes))

(defun pointer->bytes (pointer size)
  (let ((buffer (make-array size :element-type '(unsigned-byte 8))))
    (loop for i below size
          do (setf (aref buffer i)
                   (cffi:mem-aref pointer :uint8 i)))
    buffer))
