#! /bin/bash

template=~/ROPER/scripts/edi_stray_template.gnuplot
dir=$1

pushd $dir
rm -f log.csv
ln -sf *.csv log.csv
cat $template | sed "s/XYZZY/${dir}/g" > plot.gnuplot
grep $dir plot.gnuplot
gnuplot plot.gnuplot

