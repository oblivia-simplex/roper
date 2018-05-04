extern crate capstone;
extern crate unicorn;

use self::capstone::prelude::*;
use self::capstone::Capstone;

use emu::loader;
use emu::loader::{Arch, Mode};
use par::statics::ARCHITECTURE;
use std::sync::Mutex;

lazy_static! {
    pub static ref X86_DISASSEMBLER: Mutex<Capstone>
        = Mutex::new(Capstone::new()
                              .x86()
                              .mode(arch::x86::ArchMode::Mode64)
                              .build()
                              .expect("Failed to initialize X86_DISASSEMBLER"));
}

lazy_static! {
    pub static ref ARM_DISASSEMBLER: Mutex<Capstone>
        = Mutex::new(Capstone::new()
                              .arm()
                              .mode(arch::arm::ArchMode::Arm)
                              .build()
                              .expect("Failed to initialize ARM_DISASSEMBLER"));
}

lazy_static! {
    pub static ref THUMB_DISASSEMBLER: Mutex<Capstone>
        = Mutex::new(Capstone::new()
                              .arm()
                              .mode(arch::arm::ArchMode::Thumb)
                              .build()
                              .expect("Failed to initialize THUMB_DISASSEMBLER"));
}

pub fn disas(insts: &Vec<u8>, mode: Mode, num_insts: usize) -> String {
    let arch = ARCHITECTURE.with_mode(mode);

    let cs = match arch {
        Arch::X86(Mode::Bits64) => X86_DISASSEMBLER.lock().unwrap(),
        Arch::Arm(Mode::Arm) => ARM_DISASSEMBLER.lock().unwrap(),
        Arch::Arm(Mode::Thumb) => THUMB_DISASSEMBLER.lock().unwrap(),
        _ => panic!("not yet implemented"),
    };
    if let Ok(dis) = cs.disasm_count(insts, 0, num_insts) {
        dis.iter()
            .map(|i| {
                format!(
                    "{} {}",
                    i.mnemonic().unwrap_or("??"),
                    i.op_str().unwrap_or("??")
                )
            })
            .collect::<Vec<String>>()
            .join("; ")
    } else {
        insts
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(" ")
    }
}
/* There seem to have been some major API changes between capstone 0.0.4 and
 * the latest version. There may or may not be a reason to try to get this
 * disas stuff up to date. 
 *
pub fn disas (insts: &Vec<u8>, mode: Mode, num_insts: usize) -> String {
    let cs_mode = match mode {
        Mode::Arm   => CsMode::MODE_LITTLE_ENDIAN,
        Mode::Thumb => CsMode::MODE_THUMB,
        Mode::Bits64 => CsMode::MODE_64,
        Mode::Bits32 => CsMode::MODE_32,
        Mode::Bits16 => CsMode::MODE_16,
        _ => panic!("haven't handled this mode yet"),
    };
    let cs_arch = match &*ARCHITECTURE {
        &Arch::Arm(_) => CsArch::ARCH_ARM,
        &Arch::Mips(_) => CsArch::ARCH_MIPS,
        &Arch::X86(_) => CsArch::ARCH_X86,
        _ => panic!("unhandled arch"),
    };
    let cs: Capstone = Capstone::new(cs_arch, cs_mode).unwrap();
    let dis: Vec<String> = 
        match cs.disasm(insts, 0, 0) {
            Some(s) => s.iter()
                        .map(|x| cs_insn_to_string(&x))
                        .take(num_insts)
                        .collect(),
            _       => {
                vec![insts.iter()
                          .map(|x| format!("{:02x}",x))
                          .collect::<Vec<String>>()
                          .join("")]
            },
        };
    format!("{}\t({:?})", dis.join("; "), mode)
}
*/
pub fn disas_static(addr: u64, num_bytes: usize, mode: Mode, num_insts: usize) -> String {
    let num_bytes = if num_bytes == 0 { 15 } else { num_bytes };
    let some_bytes = loader::read_static_mem(addr, num_bytes);
    if let Some(bytes) = some_bytes {
        //println!("STATIC: {:?}, {} bytes: {:?}", mode, size, bytes);
        format!("{:08x}\t{}", addr, disas(&bytes, mode, num_insts))
    } else {
        format!("[INVALID ADDRESS: {:08x}]", addr)
    }
}
