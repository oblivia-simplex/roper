set terminal png size 1024,512
set datafile commentschars "%"
set multiplot layout 1, 2 
set key autotitle columnhead
set datafile separator ","
set autoscale
set tics font "Helvetica,8"
plot "./roper_14-27-08.csv" u 2:3 w lines,\
  "" u 2:4 w lines,\
  "" u 2:5 w lines,\
  "" u 2:7 w lines,\
  "" u 2:8 w lines lt rgb "#555555"
plot "./roper_14-27-08.csv" u 1:2 w lines,\
  "" u 1:10 w lines,\
  "" u 1:6 w lines,\
  "" u 1:11 w lines
unset multiplot
