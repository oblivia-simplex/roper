(in-package #:asdf-user)

(asdf:defsystem #:cl-unicorn
  :serial t
  :description "Interface to the Unicorn Emulation Library
(Limited, for now, to what's needed by ROPER)"
  :author "Oblivia Simplex <oblivia@paranoici.org>"
  :depends-on (#:cffi)
  :components ((:file "package") (:file "unicorn")))
