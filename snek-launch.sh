#! /bin/bash
PROJECT_ROOT=`pwd`

echo -n "PORT: "
read GAMEPORT
echo $GAMEPORT


function labelmaker () 
{
  SRC=/dev/urandom
  len=6
  i=1
  (
  while (( $i <= len )); do
    if (( ($i + 1) % 3 == 0 )) ; then
      cat $SRC | tr -dc aeiouy | head -c1
    else
      cat $SRC | tr -dc qwrtpsdfghjklzxcvbnm | head -c1
    fi
    # (( $i > 0 )) && (( $i % 6 == 0 )) && echo -n "_"
    i=$(( $i + 1 ))
  done
  ) | sed s:-$::
  echo
}

DATAFILE=${PROJECT_ROOT}/data/iris.small #data_banknote_authentication.txt
PATTERNSTRING="-p 02bc3e 02bc3e 0 _ _ _ _ 0b" 
DATASTRING="-d $DATAFILE"
BINARY=${PROJECT_ROOT}/data/tomato-RT-N18U-httpd
GOAL="0.01"
READEVERY=1
LABEL=`labelmaker`
TERMINALSTRING=""

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
BEST_TIME=15
UNSEEN=16
CLASS0_MEANDIF=17 
CLASS1_MEANDIF=19
CLASS2_MEANDIF=21
CLASS3_MEANDIF=23
CLASS4_MEANDIF=25
CLASS5_MEANDIF=27
CLASS6_MEANDIF=29
CLASS7_MEANDIF=31
CLASS8_MEANDIF=33
CLASS9_MEANDIF=35
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
                             -- -a "localhost:$GAMEPORT"\
                                -b $BINARY \
                                -o $PROJECT_ROOT/logs \
                                -g $GOAL \
                                -c 0.2 \
                                -s 1.0 \
                                -P 2048 \
                                -t 1 \
                                -D 4 \
                                -m 0.05 \
                                -V \
                                -R \
                                -L $LABEL 
                                
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
  recent=`find ./ -newer $STAMPFILE -name "${LABEL}*csv"`
done
echo -e "\nLABEL is $LABEL\n*** recent csv -> $recent"
TIMESTAMP=`grep -oP '[01]?[0-9]-[0-5][0-9]-[0-5][0-9]' <<< $recent`
echo "TIMESTAMP: $TIMESTAMP"
export TIMESTAMP
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
  echo "every $READEVERY u ${X1}:(\$${mcol}+\$${scol}):(\$${mcol}-\$${scol}) w filledcurves lc $colour title 'C$1 STDDEV'"
}
function difplotline ()
{
  class=$(( 2 * $1 ))
  colour=$(( $1 + 1 ))
  mcol=$(( $class + $CLASS0_MEANDIF ))
  echo "every $READEVERY u ${X1}:$mcol w lines lc $colour title 'C$1 MEAN'"
}
function plotdbg ()
{
  class=$1
  mcol=$(( $class * 2 + $CLASS0_MEANDIF ))
  scol=$(( $mcol + 1))
  echo "print \"class $class mean+stddev > (\$${mcol}+\$${scol})\""
  echo "print \"class $class mean-stddev > (\$${mcol}-\$${scol})\""
}
function popplotline ()
{
  col=$1
  echo "u ${X1}:${col} w lines"
}
cat > $PLOTFILE << EOF
$TERMINALSTRING
$OUTPUTSTRING
set datafile commentschars "%"
set multiplot layout 1, 2  
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
plot "$PROJECT_ROOT/logs/$recent" $(popplotline $AVG_FIT) , \
  "" $(popplotline $AVG_ABFIT), \
  "" $(popplotline $AVG_CRASH), \
  "" $(popplotline $MIN_FIT), \
  "" $(popplotline $BEST_FIT),  \
  "" $(popplotline $MIN_ABFIT), \
  "" $(popplotline $BEST_ABFIT)

set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.5 
plot "$PROJECT_ROOT/logs/$recent" $(difplotline 0), \
  "" $(difplotline 1), \
  "" $(difplotline 2), \
  "" $(difplotline 3), \
  "" $(difplotline 4), \
  "" $(difplotline 5), \
  "" $(difplotline 6), \
  "" $(difplotline 7), \
  "" $(difplotline 8), \
  "" $(difplotline 9)

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
( [ -n "$DISPLAY" ] && gnuplot $PLOTFILE 2>> /tmp/gnuplot-err.txt) &
gnuplot_pid=$!
echo "[+] gnuplot PID is $gnuplot_pid"
for i in {0..70}; do echo -n "="; done; echo
tail -n 4096 -f $OUTFILE
kill $roper_pid
[ -n "$DISPLAY" ] && kill $gnuplot_pid
rm $OUTFILE
rm $ERRORFILE
