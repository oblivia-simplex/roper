
function get_chain_idx (path) {
    return gensub(/^.*\/chain_([0-9]+)_visited_map.txt$/, "\\1", 1, path)
}

function get_season_num (path) {
    return gensub(/^.*season_([0-9]+)_dump.*$/, "\\1", 1, path)
}

function from_hex (h) {
    return strtonum("0x" h)
}

function from_hex_signed (h) {
    max = 2 ^ 32
    med = max / 2
    num = strtonum("0x" h)
    return ((num < med) ? num : ( (num > med) ? num - max : -med ))
}

function unwrap_some (s) {
    return gensub(/Some\(([^)]*)\)/, "\\1", 1, s)
}


function parse_crash (rec) {
    c = gensub(/Crashes: +Some\((true|false)\).*$/, "\\1", 1, rec)
    return c ~ "true"
}

function parse_problem (p) {
    dotted = gensub(/^--- BEGIN VISIT MAP FOR PROBLEM ([0-9a-f.]+). /, "\\1", 1, p)
    hexints[1] = ""
    split(dotted, hexints, ".")
    ints = ""
    for (h in hexints) {
        ints = ints OFS (from_hex_signed(hexints[h]) / 100.0)
    }
    return ints 
}


BEGIN {
    # disabling headers for use in bash loop visit_scape script
#    print "SEASON", "INDEX", "PROBLEM", "ADDRESS", "STRAY", "FITNESS", "CRASH"
}


# Extract the chain index from the filename
# and the season number from the directory name

FNR == 1 {
    idx = get_chain_idx(FILENAME);
    problem = 0;
    if (idx !~ /^[0-9]+$/) { idx = 0 };
    #season = get_season_num(FILENAME);
}

/^Relative Fitness/ { fitness = unwrap_some($3); season = gensub(/([0-9]+)\] *$/, "\\1", 1, $5) }

/^Crashes: +Some/ { crash = (unwrap_some($2) ~ "true"); next }

/--- BEGIN VISIT MAP FOR PROBLEM.*/ { input=parse_problem($0); visit=1; rc=0; ++problem; next }

visit && $1 ~ /[0-9a-f]+/ {
    j=1
    stray = ($0 ~ "stray")
    rows[++rc] = season OFS idx OFS problem OFS rc OFS from_hex($1) OFS stray OFS fitness;
    next
}

# just grabbing the first few for now, so that i can plot classification results
visit && $1 ~ "OUT:" { 
  c0 = from_hex_signed(gensub(/->[0-9a-f]+/, "", 1, $4)) 
  c1 = from_hex_signed(gensub(/->[0-9a-f]+/, "", 1, $5))  # regs 2 and 3, immed
  output = (c0 < c1)
  next
}

/--- END VISIT MAP FOR PROBLEM.*/   {
    visit=0;
##    if (input ~ /./ && output ~ /./) print input, output
## uncomment for loop for visit data. 
    for (row in rows)
    {
        # If the chain crashes, flag this crash at the last address visited.
        c = ((row ~ rc) && crash)
        print rows[row], c
    }
    next
}



END {
    #print ""
}
