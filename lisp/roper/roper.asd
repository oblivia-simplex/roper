(in-package #:asdf-user)

(asdf:defsystem #:roper
  :serial t
  :description "ROPER RIDES AGAIN!"
  :depends-on (#:elf
	       #:cl-unicorn
	       #:junk-drawer
	       #:cl-mersenne
	       #:cffi
	       #:screamer)
  :components ((:file "packages")
	       (:file "read-elf")
	       (:file "phylostructs")
	       (:file "mips-analysis")
	       (:file "arm-analysis")
	       (:file "2ndvariety")
	       (:file "hatchery")
	       (:file "roper")
	       (:file "ropush-vars")
	       (:file "ropush-gad")
	       (:file "ropush")
	       ))
