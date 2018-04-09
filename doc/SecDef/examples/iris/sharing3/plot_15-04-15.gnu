#set terminal png truecolor background rgb "black" size 1660,1024

set datafile commentschars "%"
set multiplot layout 1, 2 
#title "ROPER on ./17/03/27/roper_15-04-15.csv"
#set xlabel 'ylabel' tc rgb 'red'
#set ylabel 'xlabel' tc rgb 'red'
#set border lc rgb 'red'
#set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
# set autoscale
set yrange [0:1]
set xlabel "TOURNEMENT ITERATION"
#set xlabel "AVERAGE GENERATION"
set ylabel "POPULATION FEATURES"
plot "./roper_15-04-15.csv" u 1:4 w lines,   "" u 1:5 w lines,   "" u 1:8 w lines,   "" u 1:6   w lines,   "" u 1:10 w lines,    "" u 1:7 w lines,   "" u 1:11 w lines
set yrange [0:1]
set xlabel "TOURNEMENT ITERATION"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.3 
plot "./roper_15-04-15.csv" every 64 u 1:16 w lines lc 1 title 'C0 MEAN',   "" every 64 u 1:($16+$17):($16-$17) w filledcurves lc 1 title 'C0 STDDEV',   "" every 64 u 1:18 w lines lc 2 title 'C1 MEAN',   "" every 64 u 1:($18+$19):($18-$19) w filledcurves lc 2 title 'C1 STDDEV',   "" every 64 u 1:20 w lines lc 3 title 'C2 MEAN',   "" every 64 u 1:($20+$21):($20-$21) w filledcurves lc 3 title 'C2 STDDEV'

unset multiplot
