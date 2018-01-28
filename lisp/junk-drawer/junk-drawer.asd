(in-package #:asdf-user)

(asdf:defsystem #:junk-drawer
  :serial t
  :description "Collection of utility functions that I haven't found a better place for, yet."
  :author "Oblivia Simplex <oblivia@paranoici.org>"
  :depends-on (#:cffi)
  :components ((:file "package")
               (:file "glue")
               (:file "stringification")
               (:file "utils")))

