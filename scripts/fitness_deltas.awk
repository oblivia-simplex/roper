
BEGIN { print "GEN","PFIT","FIT","DELTA", "EDIRATE" }

/^Relative Fitness:/ { fit=gensub(/Some\(([0-9.]+)\)/, "\\1", 1, $3) }

/^Generation:/ { gen = $2 }

/^Ancestral Fitness:/ { 
    afstr = gensub(/^Ancestral Fitness: \[([^\]]*)\]/, "\\1", 1, $0);
    if (afstr == "") nextfile;
    if (afstr ~ ",") { split(afstr,afs,",") } else { afs[0] = afstr };
    sum = 0;
    len = length(afs);
    for (i=0; i<len; i++) sum += afs[i];
    if (!(len == 0 || (len == 1 && afs[i] == 0))) {
        mean = sum / len;
        if (mean == 0) {
            nextfile
        } else {
            delta = (fit - mean) / mean
        }
        row = gen OFS mean OFS fit OFS delta
    } else {
        nextfile
    }
}

/^Clumps:/ { clumps=1; enabled=0; disabled=0; next }

clumps && /^\[\*\]/ { enabled ++; next }
clumps && /^\[ \]/  { disabled ++; next }

/^Packed:/ {
  clumps=0;
  edirate = disabled / (enabled + disabled);
  print row, edirate
}
