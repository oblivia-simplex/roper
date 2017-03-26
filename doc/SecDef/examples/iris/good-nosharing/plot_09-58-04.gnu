set terminal png size 1024,512
set datafile commentschars "%"
set multiplot layout 1, 2 
set key autotitle columnhead
set datafile separator ","
set autoscale
set tics font "Helvetica,8"
plot "./roper_09-58-04.csv" u 2:3 w lines,\
  "" u 2:4 w lines,\
  "" u 2:6 w lines
#  "" u 2:10 w lines
plot "./roper_09-58-04.csv" u 1:2 w lines,\
  "" u 1:8 w lines,\
  "" u 1:5 w lines,\
  "" u 1:9 w lines
unset multiplot
