#! /bin/bash

# i'm using nginx for the webserver on this box
cd $( dirname "${BASH_SOURCE[0]}" ) 

NOSERVE=1
PROJECT_ROOT=`pwd`/..
[ -n "$BINARY" ] || BINARY=$1
[ -n "$BINARY" ] || BINARY=${PROJECT_ROOT}/data/tomato-RT-N18U-httpd

if [ -n "$BARE_RUN" ]; then
    ROPER_THREADS=1
    BUILD_FLAGS=""
else
    [ -n "$ROPER_THREADS" ] || ROPER_THREADS=4
fi


INDEXSUFFIX="" # for simulataneous runs, etc.

if [ -z "$POPULATION" ]; then
    POPULATION=2048
fi

DATAFILE=${PROJECT_ROOT}/data/iris.data #data_banknote_authentication.txt
#exec_str_addr=0001bc3e # /bin/sh\n
exec_str_addr=0001f62f # /tmp/flashXXXX in tomato-RT-N18U. in writeable mem! 
PATTERNSTRING="-p ${exec_str_addr},\&${exec_str_addr},0,_,_,_,_,0b" 
DATASTRING="-d $DATAFILE"
READEVERY=1

CLASSIFICATION=0

function add_flag() {
  grep -q "\\$1" <<< "x$EXTRAFLAGS" || \
    EXTRAFLAGS="$EXTRAFLAGS $1 $2" && \
    echo "[+] Added flag $1 $2"
  echo "EXTRAFLAGS> $EXTRAFLAGS"
  export EXTRAFLAGS
}

[ -n "$PROBLEM" ] || PROBLEM=iris
case "$PROBLEM" in
    syscall)
        TASKFLAGS=$PATTERNSTRING
        GOAL=0.0
        add_flag --crossover 0.5 
        add_flag --fitness_sharing
        add_flag --crash_penalty 0.2
        ;;
    iris)
        TASKFLAGS=$DATASTRING
        GOAL=0.00
        CLASSIFICATION=1
        add_flag --crossover 0.5 
        add_flag --crash_penalty 0.5
        add_flag --fitness_sharing
        add_flag --dynamic_crash_penalty
        add_flag --stack_input_sampling 0.2
        ;;
    2blobs)
        TASKFLAGS="-d ${PROJECT_ROOT}/data/2_simple_blobs.csv -N 2 -Z 2"
        GOAL=0.0
        CLASSIFICATION=1
        add_flag --fitness_sharing
        add_flag --crossover 0.5 
        add_flag --crash_penalty 1.0
        ;;
    deadsimple)
        TASKFLAGS="-d ${PROJECT_ROOT}/data/deadsimple.csv -N2 -Z2"
        GOAL=0.0
        CLASSIFICATION=1
        add_flag --crossover 0.5 
        add_flag --crash_penalty 0.5
        ;;
    3blobs)
        TASKFLAGS="-d ${PROJECT_ROOT}/data/3_simple_blobs.csv -N 2 -Z 3"
        GOAL=0.0
        CLASSIFICATION=1
        add_flag --crossover 0.5 
        add_flag --fitness_sharing
        add_flag --crash_penalty 0.5
        add_flag --stack_input_sampling 0.2
        ;;
    kafka)
        TASKFLAGS="-K"
        GOAL=0.0
        #add_flag --crossover 0.5 
        add_flag --crossover 1.0 # to study drift
        add_flag --crash_penalty 0.0
        ;;
    *)
        echo "[X] Did not recognize \$PROBLEM=\"$PROBLEM\""
        exit 1
        ;;
esac

export RUSTFLAGS=-Awarnings
SRV=${PROJECT_ROOT}/srv
mkdir -p $SRV

function webserver () 
{
  cd $SRV
  echo "[+] Serving plots and logs on port 8888..." >&2
  python -m SimpleHTTPServer 8888 &> $SRV/httpd.log.txt &
  echo "$?"
}



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

LABEL=`labelmaker`

LOGDIR_REL=`date +logs/%y/%m/%d/${LABEL}/`
LOGDIR="${PROJECT_ROOT}/${LOGDIR_REL}"
mkdir -p $LOGDIR
OUTFILE="${LOGDIR}/${LABEL}.out"
ERRORFILE="${LOGDIR}/${LABEL}.err"
PLOTFILE=${LOGDIR}/${LABEL}.gnuplot
CSVFILE=${LOGDIR}/${LABEL}.csv
GITNOTE=${LOGDIR}/git_note.log
git log | head -n6 > $GITNOTE


## CSV FIELDS. why not just use strings?
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
RATIO_RUN=22
AVG_INSTS=23
XOVER_DELTA=24
MUT_DELTA=25
TTL_RATIO=26
C=27

CLASS0_MEANDIF=$(( C + 0 ))
CLASS0_STDDEVDIF=$(( C + 1 ))
CLASS1_MEANDIF=$(( C + 2 ))
CLASS1_STDDEVDIF=$(( C + 3 ))
CLASS2_MEANDIF=$(( C + 4 ))
CLASS2_STDDEVDIF=$(( C + 5 ))
X0=$AVG_GEN
X1=$ITERATION
X0_AXIS_TITLE="AVERAGE GENERATION"
X1_AXIS_TITLE="TOURNAMENT ITERATION"

echo "[+] compiling roper..."
echo "[+] logging stderr to $ERRORFILE"
cargo build $BUILD_FLAGS 2>&1 | tee -a $ERRORFILE || \
  (cat $ERRORFILE && exit)
echo "[+] roper has been successfully compiled"
STAMPFILE="/tmp/.roper_starting"
rm -f $STAMPFILE
touch $STAMPFILE
DISASFILE="/tmp/roper_disassembly.txt" 
[ -f "$DISASFILE" ] && mv $DISASFILE \
  $PROJECT_ROOT/logs/roper_disassembly.old.txt
function run () {
  echo "[+] POPULATION=$POPULATION"
  CMD="RUST_BACKTRACE=1 cargo run \
                             -- ${TASKFLAGS} \
                                --binary $BINARY \
                                --logs $PROJECT_ROOT/logs \
                                --sample_ratio 1.0 \
                                --population $POPULATION \
                                --threads $ROPER_THREADS \
                                --demes 4 \
                                --migration 0.05 \
                                -E \
                                --edi_toggle_rate 0.3 \
                                --init_length 32 \
                                --label $LABEL \
                                $EXTRAFLAGS"
  CMD=$(sed "s/  */ /g" <<< "$CMD")
  echo -ne "[*] Running ROPER with command:\n\t"
  echo "sh -c \"$CMD\""
  sh -c "$CMD"
                                
}

if (( $BARE_RUN )) ; then
  run
  exit 0
fi

(( $NOSERVE )) || WEBSRV_PID=$(webserver)
recent=""


IMAGE_EXT="svg"
IMAGEFILE=${LABEL}.${IMAGE_EXT}
TERMINALSTRING="set terminal svg background rgb \"black\" size 1660,1024"
OUTPUTSTRING="set output \"${SRV}/${IMAGEFILE}\""

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
  echo "u ${X1}:${col} w lines lw 3"
}
cat > $PLOTFILE << EOF
$TERMINALSTRING
$OUTPUTSTRING
set datafile commentschars "%"
EOF
if (( $CLASSIFICATION )); then
    cat>> $PLOTFILE <<EOF
set multiplot layout 1, 2  
EOF
fi

cat>> $PLOTFILE <<EOF
set xlabel 'ylabel' tc rgb 'red'
set ylabel 'xlabel' tc rgb 'red'
set border lc rgb 'red'
set key tc rgb 'red'
set key autotitle columnhead
set datafile separator ","
set autoscale
#set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "POPULATION FEATURES"
plot "$CSVFILE" $(popplotline $AVG_FIT) , \
  "" $(popplotline $AVG_ABFIT), \
  "" $(popplotline $AVG_CRASH), \
  "" $(popplotline $EDI_RATE), \
  "" $(popplotline $MIN_FIT), \
  "" $(popplotline $BEST_FIT), \
  "" $(popplotline $MIN_ABFIT), \
  "" $(popplotline $BEST_ABFIT), \
  "" $(popplotline $STRAY_RATE), \
  "" $(popplotline $RATIO_RUN), \
  "" $(popplotline $XOVER_DELTA), \
  "" $(popplotline $VISIT_DIVERS), \
  "" $(popplotline $TTL_RATIO)
EOF

if (( $CLASSIFICATION )); then
    cat >> $PLOTFILE <<EOF
set yrange [0:1]
set xlabel "$X1_AXIS_TITLE"
set ylabel "DIFFICULTY BY CLASS"
set style fill transparent solid 0.3 
plot "$CSVFILE" $(difplot 0), \
  "" $(difplot 1), \
  "" $(difplot 2), \
  "" $(difplotline 0), \
  "" $(difplotline 1), \
  "" $(difplotline 2)

unset multiplot
EOF
fi

cat >> $PLOTFILE <<EOF
unset output
pause 60
reread
EOF

cat > $SRV/$LABEL.html<<EOF
<meta http-equiv="refresh" content="60">
<a href="${LOGDIR_REL}">
<img src="${IMAGEFILE}" style="width: 100%; height: 100%" />
</a>
EOF

echo "[+] logging to $CSVFILE"

function plot () {
    while ! [ -f $CSVFILE ]; do
        sleep 1
    done
    gnuplot $PLOTFILE 2>> /tmp/gnuplot-err.txt 
}

plot &
run



