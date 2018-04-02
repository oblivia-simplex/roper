#! /bin/bash

# run from top level of date directory for logs
mkdir -p ~/ROPER/srv/heatmaps
for d in `ls`; do pushd $d; heatmaps=`find . -type f -name "*heatmap*.png" | sort -t_ -k3 -n`; [ -n "$heatmaps" ] && convert -delay 25 -loop 1 $heatmaps ~/ROPER/srv/heatmaps/${d}_heatmap.gif && echo "made time lapse gif for $d"; popd; done

