        .section .text
        .globl _start

_start:


        
        eor     r0, r0, r0
        add     r0, r0, #5
        mov     r1, #10
        mov     r2, #15
        mov     r3, #0x0e
        mov     pc, lr

