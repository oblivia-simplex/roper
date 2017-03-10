#! /bin/bash
PROJECT_ROOT=`pwd`
DATAFILE=${PROJECT_ROOT}/data/iris.small
GOAL="0.10"
OUTFILE="${PROJECT_ROOT}/data/roper.out"

mkdir -p $PROJECT_ROOT/logs

ITERATION=1
AVG_GEN=2
AVG_FIT=3
AVG_CRASH=4
BEST_GEN=5
BEST_FIT=6
BEST_CRASH=7
AVG_LEN=8
BEST_LEN=9
X=$AVG_GEN
cat > plot.gnu << EOF
set title "ROPER on $DATAFILE"
set terminal x11 background rgb 'black'
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set yrange [0.0:1.0]
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
set autoscale
set xlabel "AVERAGE GENERATION"
set ylabel "POPULATION FEATURES"
plot "logs/recent.csv" u ${X}:${AVG_FIT} w lines, \
  "" u ${X}:${AVG_CRASH} w lines, \
  "" u ${X}:${BEST_FIT} w lines
pause 1 
reread
EOF
# "logs/recent.csv" u $AVG_GEN:$AVG_LEN w lines, \
# "logs/recent.csv" u $AVG_GEN:$BEST_LEN w lines

cargo build || exit

rm -f /tmp/.roper_starting
touch /tmp/.roper_starting
function run () {
  cargo run -- -d $DATAFILE -o $PROJECT_ROOT/logs -g $GOAL -t 4
}
run > $OUTFILE &
roper_pid=$!
echo "roper_pid is $roper_pid"
cd $PROJECT_ROOT/logs
gzip roper*.csv
recent=""
while ! [ -n "$recent" ]; do
  sleep 0.5
  recent=`find ./ -name "roper*csv" -anewer /tmp/.starting | tail -n1`
done
ln -sf $recent recent.csv
cd ..
echo "[+] logging to $PROJECT_ROOT/logs/$recent"
sleep 1
( [ -n "$DISPLAY" ] && gnuplot plot.gnu) &
gnuplot_pid=$!
echo "gnuplot_pid is $gnuplot_pid"
tail -f $OUTFILE
kill $roper_pid
[ -n "$DISPLAY" ] && kill $gnuplot_pid
gzip $PROJECT_ROOT/logs/$recent



