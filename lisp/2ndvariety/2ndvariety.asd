(in-package #:asdf-user)

(asdf:defsystem #:2ndvariety
  :serial t
  :description "Constraint-solving tool for extracting gadgets"
  :depends-on (#:arm-analysis
               #:read-binary
               #:elf
               #:screamer
               #:cl-unicorn
               #:junk-drawer)
  :components ((:file "packages")
               (:file "2ndvariety")))
