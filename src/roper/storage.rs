

fn read_popfile (path: &str) -> Vec<Vec<Clump>> {
  let f = File::open(path).expect("Failed to read file");
  let mut file = BufReader::new(&f);
  file.lines()
      .map(|x| deserialize_chain(&(x.unwrap())))
      .collect()
}

// have a separate file format and function to read 
// parameters. no reason not to keep these distinct.

// let the format for each gadget be:
// sp_delta;ret_offset;addr,pad,pad...
fn deserialize_clump(gad: &str) -> Clump {
  let fields : Vec<&str> = gad.split(';').collect();
  let words : Vec<u32> = fields[4].split(',')
                                  .map(|x| x.parse::<u32>()
                                             .unwrap())
                                  .collect();
  
  let mode : MachineMode = match fields[0] {
    "THUMB" => MachineMode::THUMB,
    "ARM"   => MachineMode::ARM,
    _       => panic!("Failed to parse MachineMode"),
  };

  let exchange : bool = match fields[1] {
    "X" => true,
    _   => false,
  };
  //let a = fields[2].parse::<u32>().unwrap();
  Clump {
    mode       : mode,
    exchange   : exchange,
    sp_delta   : fields[0].parse::<i32>().unwrap(),
    ret_offset : fields[1].parse::<i32>().unwrap(),
    words      : words,
    ..Default::default()
  } 
  
}

fn deserialize_chain (row: &str) -> Vec<Clump> {
  row.split(' ').map(deserialize_clump).collect()
}

