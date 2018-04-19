#! /bin/bash

if [ -z "$1" ]; then
    echo "Usage $0 <population name>"
    exit 1
fi


OUTFILE=""
SPECIMEN=""
IRISDATA=""
POPNAME=""
POPDIR=""
ITERATION=""
PROCESSED_SPECIMENS=""
PLOTLIST=""

function make_gnuplot_script () {
    gp_tmp=$(mktemp)
    cat ~/ROPER/scripts/iris_template.gnuplot \
        | sed "s%XXX_OUTPUT_XXX%$OUTFILE%" \
        | sed "s%XXX_SPECIMEN_XXX%$SPECIMEN of $POPNAME, Iteration $ITERATION%" \
        | sed "s%XXX_IRIS_DATA_XXX%$IRISDATA%" \
        > $gp_tmp
    if ! gnuplot $gp_tmp
    then
        echo "[X] Gnuplot failed. See $gp_tmp for plot script."
        exit 1
    fi
    rm $gp_tmp
}

function scrape_data () {
    IRISDATA=`mktemp`
    awk -f ~/ROPER/scripts/class_scraper.awk $1 > $IRISDATA
}

function make_montage() {
    echo "[+] Making montage of $PLOTLIST"
    rm -f ${POPNAME}_iris_montage.pdf
    montage -geometry +1+1 ~/ROPER/scripts/iris_plot.pdf $PLOTLIST ${POPNAME}_iris_montage.pdf
}

function set_population_vars () {
    POPDIR=$(echo ~/ROPER/logs/*/*/*/$POPNAME)
    if ! [ -d "$POPDIR" ]; then
        echo "[x] could not find $POPDIR directory."
        exit 1
    fi
    pushd $POPDIR
}
        
function set_specimen_vars () {
    specfile=$1
    SPECIMEN=`grep -oP "(?<=^Synopsis of chain )[a-z]{6}-[a-z]{6}" $specfile`
    #ITERATION=`grep -oP "(?<=\[Season )[0-9]+(?=\])" $specfile`
    ITERATION=`sed "s/${POPNAME}_champion_[0-9-]*_\([0-9]*\)_visited.txt/\1/" <<< $specfile`
    OUTFILE="${POPNAME}_${ITERATION}_${SPECIMEN}.pdf"
}

function showvars () {
    echo "POPNAME = $POPNAME"
    echo "POPDIR = $POPDIR"
    echo "SPECIMEN = $SPECIMEN"
    echo "ITERATION = $ITERATION"
    echo "OUTFILE = $OUTFILE"
    echo "IRISDATA = $IRISDATA"
}

function add_to_plotlist () {
    PLOTLIST=`echo "$PLOTLIST $1" | sort -t_ -k2 -n | uniq`
}

if [ -z "$1" ]; then
    echo "Usage $0 <population name>"
    exit 1
fi
POPNAME=$1
set_population_vars

while :; do 
    for champ in `ls $POPNAME_*champion*.txt`; do
        if (grep -q $champ <<< "$PROCESSED_SPECIMENS"); then
            continue
        fi
        echo "[-] setting specimen vars for $champ"
        set_specimen_vars $champ
        scrape_data $champ
        showvars
        make_gnuplot_script
        PROCESSED_SPECIMENS="$PROCESSED_SPECIMENS $champ"
        add_to_plotlist $OUTFILE
        echo
    done
    [ -n "$PLOTLIST" ] && make_montage
    echo "waiting for new champions"
    sleep 5
done
exit

