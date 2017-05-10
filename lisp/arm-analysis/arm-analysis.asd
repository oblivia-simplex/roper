(in-package #:asdf-user)

(asdf:defsystem #:arm-analysis
  :serial t
  :description "Tools for analysing ARM binaries."
  :author "Oblivia Simplex <oblivia@paranoici.org>"
  :depends-on (#:elf #:junk-drawer)
  :components ((:file "package") (:file "arm-analysis")))
