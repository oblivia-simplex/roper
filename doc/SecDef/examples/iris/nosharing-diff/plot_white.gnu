set terminal png truecolor size 1024,640

set datafile commentschars "%"
set multiplot layout 1, 2  
set key autotitle columnhead
set datafile separator ","
# set autoscale
set yrange [0:1]
set xlabel "TOURNEMENT ITERATION"
set ylabel "POPULATION FEATURES"
plot "./cazmud_01-00-33_short.csv" u 1:4 w lines ,   "" u 1:5 w lines,   "" u 1:8 w lines,   "" u 1:6 w lines,   "" u 1:10 w lines,    "" u 1:7 w lines,   "" u 1:11 w lines

set yrange [0:1]
set xlabel "TOURNEMENT ITERATION"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.5 
plot "./cazmud_01-00-33_short.csv" every 16 u 1:($17+$18):($17-$18) w filledcurves lc 1 title 'C0 STDDEV',   "" every 16 u 1:($19+$20):($19-$20) w filledcurves lc 2 title 'C1 STDDEV',   "" every 16 u 1:($21+$22):($21-$22) w filledcurves lc 3 title 'C2 STDDEV',   "" every 16 u 1:17 w lines lc 1 title 'C0 MEAN',   "" every 16 u 1:19 w lines lc 2 title 'C1 MEAN',   "" every 16 u 1:21 w lines lc 3 title 'C2 MEAN'

unset multiplot
