#! /bin/bash

S=$1
IN=$2
OUT=$3

arm-none-eabi-objdump -h $IN | grep $S |
    awk '{print "dd if='$IN' of='$OUT' bs=1 count=$[0x" $3 "] skip=$[0x" $6 "]"}' |
    bash
