        .section .text
        .globl _start

_start:


        xor      %rax, %rax
        movq     $0x100, %rax
        movq     $0x7, %rsi
        movq     $0x8, %rdi
        movq     $0x10, %r10
        movq     $0x9, %r9
        movq     $0xdeadbeef, %rax
        //        int      $0x80
        ret
