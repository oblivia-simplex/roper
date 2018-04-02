#! /bin/bash

dir=$1

if [ -z "$dir" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

function getsome () {
    grep -oP "(?<=Some\()[0-9.]+(?=\))"
}

function avg_stray_by_fit () {
    awk -F, 'BEGIN { OFS=","} { if (!keys[$1]) { keys[$1] = 1 }; array[$1,2]+=$2; count[$1]+=1 } END { for (i in keys) { printf ("%s,", i); printf ("%.8f ", array[i,2]/count[i]); printf ("%s","\n") } }' $1
}
function avg_fit_by_stray () {
    awk -F, 'BEGIN { OFS=","} { if (!keys[$2]) { keys[$2] = 1 }; array[$2,1]+=$1; count[$2]+=1 } END { for (i in keys) { printf ("%s,", i); printf ("%.8f ", array[i,1]/count[i]); printf ("%s","\n") } }' $1
}

tmp=$(mktemp)

# this is a horrible horrible piece of code, but i don't care right now
function count_implicit_stray () {
    stray=$(mktemp)
    all=$(mktemp)
    awk '/BEGIN VISIT MAP/{flag=1;next}/END VISIT MAP/{flag=0}flag' \
        | tee >(grep -P "^[0-9a-f]{8}" > $all) \
        | grep stray > $stray
    straylines=$(wc $stray | awk '{print $1}')
    alllines=$(wc $all | awk '{print $1}')
    echo "stray: $straylines out of $alllines" >&2
    rm $stray $all
    echo "$straylines / $alllines" | bc -l
}

find $dir -type f -name "*.txt" \
    | while read f; do
        abfit=$(head -n 256 $f | grep "Absolute Fitness" | getsome) 
        [ -n "$abfit" ] || continue
        stray=""
        (( $USE_IMPLICIT_COUNT )) || stray=$(head -n 256 $f | grep "Stray Rate" | awk '{print $3}')
        [ -n "$stray" ] || stray=$(cat $f | count_implicit_stray)
        echo "$abfit,$stray"
    done | tee $tmp


echo "STRAY BY FIT:"
avg_stray_by_fit $tmp | tee ./stray_by_fit.txt
echo "FIT BY STRAY:"
avg_fit_by_stray $tmp | tee ./fit_by_stray.txt
rm $tmp





