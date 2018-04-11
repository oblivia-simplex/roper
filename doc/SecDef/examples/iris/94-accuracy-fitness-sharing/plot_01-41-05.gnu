#set terminal png background rbg "black" size 1024,768
#set output "roper_01-41-05.png"
set datafile commentschars "%"
set multiplot layout 1, 2 title "ROPER on ./17/03/26/roper_01-41-05.csv"
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
# set autoscale
set xlabel "AVERAGE GENERATION or TOURNEMENT ITERATION"
set ylabel "POPULATION FEATURES"
plot "roper_01-41-05.csv" u 3:4 w lines,   "" u 3:5 w lines,   "" u 3:8 w lines,   "" u 3:6   w lines,   "" u 3:10 w lines,    "" u 3:7 w lines,   "" u 3:11 w lines
plot "roper_01-41-05.csv" u 1:3 w lines,   "" u 1:13 w lines,   "" u 1:9 w lines,   "" u 1:14 w lines
pause 2 
unset multiplot
