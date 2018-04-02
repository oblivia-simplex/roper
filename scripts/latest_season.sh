#! /bin/bash

dir=$1

find $dir -maxdepth 1 -type d -exec sh -c "find {} -type d -name "*season*" | sort -t_ -n -k3 | tail -n1" \; \
    | sort -u \
    | sort -t_ -k3 -n \
    | sed "s,^.*/\([a-z]\+\)_season_\([0-9]*\)_dump,\1: \2," \

    
