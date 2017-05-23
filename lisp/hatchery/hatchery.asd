(in-package #:asdf-user)

(asdf:defsystem #:hatchery
  :serial t
  :description "Utilities for operating the unicorn machinery"
  :depends-on (#:read-binary
               #:elf
               #:cl-unicorn
               #:junk-drawer)
  :components ((:file "packages")
               (:file "hatchery")))
