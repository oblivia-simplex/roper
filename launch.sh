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
X0=$AVG_GEN
X1=$ITERATION
X0_AXIS_TITLE="AVERAGE GENERATION"
X1_AXIS_TITLE="TOURNEMENT ITERATION"

cat > plot.gnu << EOF
set terminal x11 background rgb 'black'
set multiplot layout 1, 2 title "ROPER on $DATAFILE"
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
set autoscale
set xlabel "$X0_AXIS_TITLE or $X1_AXIS_TITLE"
set ylabel "POPULATION FEATURES"
plot "logs/recent.csv" u ${X0}:${AVG_FIT} w lines, \
  "" u ${X0}:${AVG_CRASH} w lines, \
  "" u ${X0}:${BEST_FIT} w lines
plot "logs/recent.csv" u ${X1}:${AVG_GEN} w lines, \
  "" u ${X1}:${AVG_LEN} w lines, \
  "" u ${X1}:${BEST_GEN} w lines, \
  "" u ${X1}:${BEST_LEN} w lines
pause 1 
unset multiplot
reread
EOF
# "logs/recent.csv" u $AVG_GEN:$AVG_LEN w lines, \
# "logs/recent.csv" u $AVG_GEN:$BEST_LEN w lines
ERRORFILE=$PROJECT_ROOT/logs/roper.err
echo "[+] logging stderr to $ERRORFILE"
cargo build 2> $ERRORFILE || \
  (cat $ERRORFILE && exit)
echo "[+] roper has been successfully compiled"
rm -f /tmp/.roper_starting
touch /tmp/.roper_starting
function run () {
  RUST_BACKTRACE=1 cargo run -- -d $DATAFILE -o $PROJECT_ROOT/logs -g $GOAL -t 4
}
echo "[+] launching roper"
run > $OUTFILE 2>> $ERRORFILE &
roper_pid=$!
echo "[+] roper PID is $roper_pid"
cd $PROJECT_ROOT/logs
gzip roper*.csv 2>> $ERRORFILE
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
echo "[+] gnuplot PID is $gnuplot_pid"
for i in {0..70}; do echo -n "="; done; echo
tail -n 4096 -f $OUTFILE
kill $roper_pid
[ -n "$DISPLAY" ] && kill $gnuplot_pid



