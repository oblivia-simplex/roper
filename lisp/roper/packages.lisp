
(defpackage :params
  (:use
   :common-lisp))


(defpackage :mips-analysis
  (:use
   :params
   :common-lisp
   :junk-drawer
   ))


(defpackage :arm-analysis
  (:use
   :params
   :common-lisp
   :junk-drawer
   ))

(defpackage :read-elf
  (:use
   :params
   :common-lisp
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

(defpackage :2ndvariety
  (:use
   :params
   :common-lisp
   :junk-drawer
   :screamer
   :read-elf
   ))

(defpackage :phylostructs
  (:use
   :params
   :common-lisp
   :2ndvariety
   :junk-drawer))

(defpackage :hatchery
  (:use
   :params
   :common-lisp
   :read-elf
   :phylostructs
   :cffi
   :junk-drawer
   :2ndvariety
   :unicorn))


(defpackage :ropush
  (:use
   :params
   :common-lisp
   :mersenne
   :junk-drawer
   :phylostructs
   ))
;; impt to first load ropush-vars, then ropush, then ropush-gad
;; and finally ropush-test, to play with it in the repl.

(defpackage :roper
  (:use
   :params
   :common-lisp
   :hatchery
   :junk-drawer
   :unicorn
   :phylostructs
   :2ndvariety
   :read-elf))

(defpackage :frontend
  (:use
   :params
   :common-lisp))
