set terminal png background rgb "black" size 1024,512
set datafile commentschars "%"
set key autotitle columnhead
set autoscale
set tics font "Helvetica,8"
set datafile separator ","
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set style histogram clustered
set boxwidth 0.25
set xtics (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
#set style fill transparent solid 1.0
plot for [i=2:5] "/tmp/ldconfig.profile" u (($1)+(i * 0.25)):i with boxes
