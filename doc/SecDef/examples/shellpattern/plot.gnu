set terminal png size 1024,512
set palette defined ( 0 "black", 1 "white" )
set datafile commentschars "%"
set multiplot layout 1, 2 title ""
set key autotitle columnhead
set datafile separator ","
set autoscale
set tics font "Helvetica,8"
plot "roper_00-10-39.csv" u 2:3 w lines,\
  "" u 2:5 w lines,\
  "" u 2:7 w lines
plot "roper_00-10-39.csv" u 1:2 w lines,\
  "" u 1:6  w lines,\
  "" u 1:10 w lines,\
  "" u 1:11 w lines
unset multiplot
