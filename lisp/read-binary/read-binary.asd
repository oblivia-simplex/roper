(in-package #:asdf-user)

(asdf:defsystem #:read-binary
  :serial t
  :description "Utilities for reading data from executables
and libraries."
  :depends-on (#:elf
               #:junk-drawer)
  :components ((:file "packages")
               (:file "read-elf")))
