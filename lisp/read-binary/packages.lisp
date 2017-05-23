(defpackage :read-elf
  (:use :common-lisp
   :junk-drawer)
  (:export :get-elf-sections
   :get-loadable-elf-segments
           :secs-in-segs
   :segment-addr
           :segment-size
   :segment-perm
           :segment-addr
   :section-addr
           :section-data
   :section-name
   :merge-segments
   ))
