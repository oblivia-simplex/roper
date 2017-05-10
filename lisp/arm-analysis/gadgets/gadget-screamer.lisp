;; A Constraint-Solving approach to gadget extraction and
;; initial population generation, perhaps

(in-package :gadget-screamer)

;; this should abstract away from the vicissitudes of the architecture
;; so each arch-analysis package should have a generic-looking interface
;; (i.e. define predicates like #'popretp, #'pop-regs, or #'jumpp.
;; there's no real need, I don't think, to flesh out an entire inter-
;; mediate language, but think of these functions as the terms of a
;; rudimentary IR).

