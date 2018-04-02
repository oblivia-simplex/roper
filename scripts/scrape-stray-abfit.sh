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

find $dir -type f -name "*.txt" \
    | while read f; do
        abfit=$(head -n 256 $f | grep "Absolute Fitness" | getsome) 
        [ -n "$abfit" ] || continue
        stray=$(head -n 256 $f | grep "Stray Rate" | awk '{print $3}')
        echo "$abfit,$stray"
    done > $tmp


echo "STRAY BY FIT:"
avg_stray_by_fit $tmp | tee ./stray_by_fit.txt
echo "FIT BY STRAY:"
avg_fit_by_stray $tmp | tee ./fit_by_stray.txt
rm $tmp





