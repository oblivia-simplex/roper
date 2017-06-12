(defpackage :read-elf
  (:use :common-lisp
   :junk-drawer)
  (:export :get-elf-sections
   :get-loadable-elf-segments
           :secs-in-segs
   :seg-addr
           :seg-size
   :seg-perm
           :segment-addr
   :sec-addr
           :sec-data
   :sec-name
   :sec-words
   :merge-segments
   ))
