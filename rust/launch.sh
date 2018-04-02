#! /bin/bash

[ -n "$ROPER_THREADS" ] || ROPER_THREADS=1
[ -n "$BARE_RUN" ] && ROPER_THREADS=1

INDEXSUFFIX="" # for simulataneous runs, etc.

POPSIZE=2048

export RUSTFLAGS=-Awarnings
PROJECT_ROOT=`pwd`/..
SRV=${PROJECT_ROOT}/srv
mkdir -p $SRV

function webserver () 
{
  cd $SRV
  echo "[+] Serving gnuplot pngs on port 8888..." >&2
  python -m SimpleHTTPServer 8888 &> $SRV/httpd.log.txt &
  echo "$?"
}



BINARY=$1
[ -n "$BINARY" ] || BINARY=${PROJECT_ROOT}/data/tomato-RT-N18U-httpd
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

DATAFILE=${PROJECT_ROOT}/data/iris.data #data_banknote_authentication.txt
PATTERNSTRING="-p 02bc3e 02bc3e 0 _ _ _ _ 0b" 
DATASTRING="-d $DATAFILE"
GOAL="0.1"
READEVERY=1
LABEL=`labelmaker`

LOGDIR_REL=`date +logs/%y/%m/%d/${LABEL}/`
LOGDIR="${PROJECT_ROOT}/${LOGDIR_REL}"
mkdir -p $LOGDIR
OUTFILE="${LOGDIR}/${LABEL}_`date +%H-%M-%S`.out"
ERRORFILE="${LOGDIR}/${LABEL}_`date +%H-%M-%S`.err"

git log | head -n6 > $OUTFILE


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
EDI_RATE=17
STRAY_RATE=18
AVG_STRAY_TO_EDI=19
STRAY_NOCRASH=20
VISIT_DIVERS=21
C=22

CLASS0_MEANDIF=$(( C + 0 ))
CLASS0_STDDEVDIF=$(( C + 1 ))
CLASS1_MEANDIF=$(( C + 2 ))
CLASS1_STDDEVDIF=$(( C + 3 ))
CLASS2_MEANDIF=$(( C + 4 ))
CLASS2_STDDEVDIF=$(( C + 5 ))
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
                                -c 0.2 \
                                -s 1.0 \
                                -P $POPSIZE \
                                -t $ROPER_THREADS \
                                -D 4 \
                                -m 0.05 \
                                -R \
                                -S \
                                -L $LABEL 
  #                              -E
  # Add -S flag to enable fitness sharing
                                
}

if (( $BARE_RUN )) ; then
  run
  exit 0
fi

(( $NOSERVE )) || WEBSRV_PID=$(webserver)
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
ln -s $OUTFILE ${LOGDIR}/${LABEL}_${TIMESTAMP}.out
ln -s $OUTFILE ${LOGDIR}/${LABEL}_${TIMESTAMP}.err
PLOTFILE=${LOGDIR}/${LABEL}_${TIMESTAMP}.gnuplot

TERMINALSTRING="set terminal png truecolor background rgb \"black\" size 1660,1024"
OUTPUTSTRING="set output \"${SRV}/${LABEL}_${TIMESTAMP}.png\""

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
set xlabel "$X1_AXIS_TITLE"
set ylabel "POPULATION FEATURES"
plot "$PROJECT_ROOT/logs/$recent" $(popplotline $AVG_FIT) , \
  "" $(popplotline $AVG_ABFIT), \
  "" $(popplotline $AVG_CRASH), \
  "" $(popplotline $EDI_RATE), \
  "" $(popplotline $MIN_FIT), \
  "" $(popplotline $BEST_FIT), \
  "" $(popplotline $MIN_ABFIT), \
  "" $(popplotline $BEST_ABFIT), \
  "" $(popplotline $STRAY_RATE), \
  "" $(popplotline $VISIT_DIVERS)

set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.3 
plot "$PROJECT_ROOT/logs/$recent" $(difplot 0), \
  "" $(difplot 1), \
  "" $(difplot 2), \
  "" $(difplotline 0), \
  "" $(difplotline 1), \
  "" $(difplotline 2)

unset multiplot
unset output
pause 4.35 
reread
EOF

cat > $SRV/$LABEL.html<<EOF
<meta http-equiv="refresh" content="60">
<a href="${LOGDIR_REL}">
<img src="${LABEL}_${TIMESTAMP}.png" style="width: 100%; height: 100%" />
</a>
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
gnuplot $PLOTFILE 2>> /tmp/gnuplot-err.txt &
gnuplot_pid=$!
echo "[+] gnuplot PID is $gnuplot_pid"

function cleanup ()
{
  trap - INT
  echo "${YELLOW}Trapped SIGINT. Cleaning up...${RESET}"
  kill $WEBSRV_PID
  kill $gnuplot_pid
  kill $roper_pid
  cat $ERRORFILE
  rm $OUTFILE
  rm $ERRORFILE
}

trap cleanup INT

for i in {0..70}; do echo -n "="; done; echo
tail -n 4096 -f $OUTFILE
[ -n "$DISPLAY" ] && kill $gnuplot_pid
