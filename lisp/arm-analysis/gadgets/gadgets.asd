(in-package #:asdf-user)

(asdf:defsystem #:gadgets
  :serial t
  :description "Tools for extracting gadgets from binaries"
  :author "Oblivia Simplex <oblivia@paranoici.org"
  :depends-on (#:elf
               #:junk-drawer
               #:screamer)
  :components ((:file "packages"
                      "gadget-screamer")))

