#! /bin/bash
export PROJECT_ROOT=`pwd`
mkdir -p $PROJECT_ROOT/logs
killall roper

cat > plot.gnu << EOF
set key autotitle columnhead
set datafile separator ","
plot "logs/recent.csv" using 2:3 with lines
pause 1
reread
EOF

rm -f /tmp/.starting
touch /tmp/.starting
function run () {
  cargo run -- -d $PROJECT_ROOT/data/iris.small -o $PROJECT_ROOT/logs -g 0.10 -t 4
}
run > /tmp/out &
cd $PROJECT_ROOT/logs
recent=""
while ! [ -n "$recent" ]; do
  sleep 0.5
  recent=`find ./ -name "roper*csv" -anewer /tmp/.starting | tail -n1`
done
ln -sf $recent recent.csv
cd ..
echo "[+] logging to $PROJECT_ROOT/logs/$recent"
sleep 1
gnuplot plot.gnu || echo "GNUPLOT DIDN'T WORK"
#tail -f /tmp/out


