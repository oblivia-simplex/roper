set terminal png size 1024,512
set datafile commentschars "%"
set multiplot layout 1, 2 
set key autotitle columnhead
set datafile separator ","
set autoscale
set tics font "Helvetica,8"
plot "./roper_02-06-08.csv" u 3:4 w lines,   "" u 3:5 w lines,   "" u 3:8 w lines,   "" u 3:6   w lines,   "" u 3:10 w lines,    "" u 3:7 w lines,   "" u 3:11 w lines
plot "./roper_02-06-08.csv" u 1:3 w lines,   "" u 1:13 w lines,   "" u 1:9 w lines,   "" u 1:14 w lines
unset multiplot
