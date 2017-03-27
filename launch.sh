#! /bin/bash
PROJECT_ROOT=`pwd`
DATAFILE=${PROJECT_ROOT}/data/iris.data
PATTERNSTRING="-p 02bc3e 02bc3e 0 _ _ _ _ 0b" 
DATASTRING="-d $DATAFILE"
BINARY=${PROJECT_ROOT}/data/tomato-RT-N18U-httpd
GOAL="0.1"

TERMINALSTRING=""

[ -n "$1" ] && LABEL="-L $1"

LOGDIR=`date +$PROJECT_ROOT/logs/%y/%m/%d`
mkdir -p $LOGDIR
OUTFILE="${LOGDIR}/roper_`date +%H-%M-%S`.out"
ERRORFILE=${LOGDIR}/roper_`date +%H-%M-%S`.err

mkdir -p $PROJECT_ROOT/logs
#gzip -f $PROJECT_ROOT/logs/roper*.{csv,json} 
ITERATION=1
SEASON=2
AVG_GEN=3
AVG_FIT=4
AVG_ABFIT=5
MIN_FIT=6
MIN_ABFIT=7
AVG_CRASH=8
BEST_GEN=9
BEST_FIT=10
BEST_ABFIT=11
BEST_CRASH=12
AVG_LEN=13
BEST_LEN=14
UNSEEN=15
CLASS0_MEANDIF=16
CLASS0_STDDEVDIF=17
CLASS1_MEANDIF=18
CLASS1_STDDEVDIF=19
CLASS2_MEANDIF=20
CLASS2_STDDEVDIF=21
X0=$AVG_GEN
X1=$ITERATION
X0_AXIS_TITLE="AVERAGE GENERATION"
X1_AXIS_TITLE="TOURNEMENT ITERATION"

# "logs/recent.csv" u $AVG_GEN:$AVG_LEN w lines, \
# "logs/recent.csv" u $AVG_GEN:$BEST_LEN w lines
echo "[+] compiling roper..."
echo "[+] logging stderr to $ERRORFILE"
cargo build | tee -a $ERRORFILE || \
  (cat $ERRORFILE && exit)
echo "[+] roper has been successfully compiled"
STAMPFILE="/tmp/.roper_starting"
rm -f $STAMPFILE
touch $STAMPFILE
DISASFILE="/tmp/roper_disassembly.txt" 
[ -f "$DISASFILE" ] && mv $DISASFILE \
  $PROJECT_ROOT/logs/roper_disassembly.old.txt
function run () {
  RUST_BACKTRACE=1 cargo run \
                             -- -d $DATAFILE \
                                -b $BINARY \
                                -o $PROJECT_ROOT/logs \
                                -g $GOAL \
                                -t 4 \
                                -P 2048 \
                                -D 1 \
                                -m 0.05 \
                                -V \
                                $LABEL
}
echo "[+] launching roper"
run 2>&1 > $OUTFILE & #2>> $ERRORFILE &
roper_pid=$!
echo "[+] roper PID is $roper_pid"
cd $PROJECT_ROOT/logs
recent=""
echo -n "[+] looking for log output"
while ! [ -n "$recent" ]; do
  if ! kill -0 $roper_pid; then
    echo "ROPER instance with PID $roper_pid is dead"
    exit
  fi
  echo -n "."
  sleep 0.5
  recent=`find ./ -name "roper*csv" -anewer $STAMPFILE | tail -n1`
done
echo "*** recent csv -> $recent"
TIMESTAMP=`grep -oP '[01]?[0-9]-[0-5][0-9]-[0-5][0-9]' <<< $recent`
ln $OUTFILE ${LOGDIR}/roper_${TIMESTAMP}.out
ln $OUTFILE ${LOGDIR}/roper_${TIMESTAMP}.err
PLOTFILE=${LOGDIR}/plot_${TIMESTAMP}.gnu
if [ -n "$DISPLAY" ]; then
  TERMINALSTRING="set terminal x11 background rgb \"black\""
  OUTPUTSTRING=""
else
  TERMINALSTRING="set terminal png background rbg \"black\" size 1024,768"
  OUTPUTSTRING="set output \"roper_${TIMESTAMP}.png\""
fi

function difplot ()
{
  class=$(( 2 * $1 ))
  colour=$(( $1 + 1 ))
  mcol=$(( $class + $CLASS0_MEANDIF ))
  scol=$(( $mcol + 1))
  echo "u ${X1}:(\$${mcol}+\$${scol}):(\$${mcol}-\$${scol}) w filledcurves lc $colour title 'C$1 STDDEV'"
}
function difplotline ()
{
  class=$(( 2 * $1 ))
  colour=$(( $1 + 1 ))
  mcol=$(( $class + $CLASS0_MEANDIF ))
  echo "u ${X1}:$mcol w lines lc $colour title 'C$1 MEAN'"
}
function plotdbg ()
{
  class=$1
  mcol=$(( $class * 2 + $CLASS0_MEANDIF ))
  scol=$(( $mcol + 1))
  echo "print \"class $class mean+stddev > (\$${mcol}+\$${scol})\""
  echo "print \"class $class mean-stddev > (\$${mcol}-\$${scol})\""
}
cat > $PLOTFILE << EOF
$TERMINALSTRING
$OUTPUTSTRING
set datafile commentschars "%"
set multiplot layout 1, 2 title "ROPER on $recent"
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
# set autoscale
set yrange [0:1]
set xlabel "$X0_AXIS_TITLE"
set ylabel "POPULATION FEATURES"
plot "$PROJECT_ROOT/logs/$recent" u ${X0}:${AVG_FIT} w lines, \
  "" u ${X0}:${AVG_ABFIT} w lines, \
  "" u ${X0}:${AVG_CRASH} w lines, \
  "" u ${X0}:${MIN_FIT}   w lines, \
  "" u ${X0}:${BEST_FIT} w lines,  \
  "" u ${X0}:${MIN_ABFIT} w lines, \
  "" u ${X0}:${BEST_ABFIT} w lines
set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.5 
plot "$PROJECT_ROOT/logs/$recent" $(difplotline 0), \
  "" $(difplot 0), \
  "" $(difplotline 1), \
  "" $(difplot 1), \
  "" $(difplotline 2), \
  "" $(difplot 2)

pause 2 
unset multiplot
reread
EOF
#plot "$PROJECT_ROOT/logs/$recent" u ${X1}:${AVG_GEN} w lines, \
#  "" u ${X1}:${AVG_LEN} w lines, \
#  "" u ${X1}:${BEST_GEN} w lines, \
#  "" u ${X1}:${BEST_LEN} w lines
ln -sf $recent recent.csv
export recent
export PLOTFILE
cd ..
echo "[+] logging to $PROJECT_ROOT/logs/$recent"
sleep 1
( [ -n "$DISPLAY" ] && gnuplot $PLOTFILE) &
gnuplot_pid=$!
echo "[+] gnuplot PID is $gnuplot_pid"
for i in {0..70}; do echo -n "="; done; echo
tail -n 4096 -f $OUTFILE
kill $roper_pid
[ -n "$DISPLAY" ] && kill $gnuplot_pid
rm $OUTFILE
rm $ERRORFILE


function plotdbg ()
{
  class=$1
  mcol=$(( $class * 2 + $CLASS0_MEANDIF ))
  scol=$(( $mcol + 1))
  echo "print \"class $class mean+stddev > (\$${mcol}+\$${scol})\""
  echo "print \"class $class mean-stddev > (\$${mcol}-\$${scol})\""
}
cat > $PLOTFILE << EOF
$TERMINALSTRING
$OUTPUTSTRING
set datafile commentschars "%"
set multiplot layout 1, 2 title "ROPER on $recent"
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
# set autoscale
set yrange [0:1]
set xlabel "$X0_AXIS_TITLE"
set ylabel "POPULATION FEATURES"
plot "$PROJECT_ROOT/logs/$recent" u ${X0}:${AVG_FIT} w lines, \
  "" u ${X0}:${AVG_ABFIT} w lines, \
  "" u ${X0}:${AVG_CRASH} w lines, \
  "" u ${X0}:${MIN_FIT}   w lines, \
  "" u ${X0}:${BEST_FIT} w lines,  \
  "" u ${X0}:${MIN_ABFIT} w lines, \
  "" u ${X0}:${BEST_ABFIT} w lines
set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.5 
plot "$PROJECT_ROOT/logs/$recent" $(difplot 0), \
  "" $(difplot 1), \
  "" $(difplot 2)

pause 2 
unset multiplot
reread
EOF
#plot "$PROJECT_ROOT/logs/$recent" u ${X1}:${AVG_GEN} w lines, \
#  "" u ${X1}:${AVG_LEN} w lines, \
#  "" u ${X1}:${BEST_GEN} w lines, \
#  "" u ${X1}:${BEST_LEN} w lines
ln -sf $recent recent.csv
export recent
export PLOTFILE
cd ..
echo "[+] logging to $PROJECT_ROOT/logs/$recent"
sleep 1
( [ -n "$DISPLAY" ] && gnuplot $PLOTFILE) &
gnuplot_pid=$!
echo "[+] gnuplot PID is $gnuplot_pid"
for i in {0..70}; do echo -n "="; done; echo
tail -n 4096 -f $OUTFILE
kill $roper_pid
[ -n "$DISPLAY" ] && kill $gnuplot_pid
rm $OUTFILE
rm $ERRORFILE


