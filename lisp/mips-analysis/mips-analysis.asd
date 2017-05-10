(in-package #:asdf-user)

(asdf:defsystem #:mips-analysis
  :serial t
  :description "Tools for analysing MIPS binaries."
  :author "Oblivia Simplex <oblivia@paranoici.org>"
  :depends-on (#:elf #:junk-drawer)
  :components ((:file "package") (:file "mips-analysis")))
