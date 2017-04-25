set terminal png size 1024,640
set datafile commentschars "%"
set multiplot layout 1, 2 
set key autotitle columnhead
set datafile separator ","
set autoscale
set tics font "Helvetica,8"
plot "./roper_15-17-17.csv" u 2:3 w lines,\
  "" u 2:4 w lines,\
  "" u 2:6 w lines,\
  "" u 2:8 w lines lt rgb "#555555",\
  "" u 2:9 w lines lt rgb "red"
plot "./roper_15-17-17.csv" u 1:2 w lines,\
  "" u 1:11 w lines,\
  "" u 1:7 w lines,\
  "" u 1:12 w lines
unset multiplot
