-- | Data.Elf  is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf ( parseElf
                , parseSymbolTables
                , findSymbolDefinition
                , Elf(..)
                , ElfSection(..)
                , ElfSectionType(..)
                , ElfSectionFlags(..)
                , ElfSegment(..)
                , ElfSegmentType(..)
                , ElfSegmentFlag(..)
                , ElfClass(..)
                , ElfData(..)
                , ElfOSABI(..)
                , ElfType(..)
                , ElfMachine(..)
                , ElfSymbolTableEntry(..)
                , ElfSymbolType(..)
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)) where

import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Data.Maybe
import Data.Word
import Numeric
import Control.Monad
import qualified Data.ByteString          as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Lazy     as L

data Elf = Elf
    { elfClass      :: ElfClass      -- ^ Identifies the class of the object file.
    , elfData       :: ElfData       -- ^ Identifies the data encoding of the object file.
    , elfVersion    :: Int           -- ^ Identifies the version of the object file format.
    , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: Int           -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: Word64        -- ^ Virtual address of the program entry point. 0 for non-executable Elfs.
    , elfSections   :: [ElfSection]  -- ^ List of sections in the file.
    , elfSegments   :: [ElfSegment]  -- ^ List of segments in the file.
    } deriving (Eq, Show)

data ElfSection = ElfSection
    { elfSectionName      :: String            -- ^ Identifies the name of the section.
    , elfSectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
    , elfSectionFlags     :: [ElfSectionFlags] -- ^ Identifies the attributes of the section.
    , elfSectionAddr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
    , elfSectionSize      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , elfSectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
    , elfSectionEntSize   :: Word64            -- ^ Size of entries if section has a table.
    , elfSectionData      :: B.ByteString      -- ^ The raw data for the section.
    } deriving (Eq, Show)

getElfMagic = do
    ei_magic <- liftM (map B.w2c) $ sequence [getWord8, getWord8, getWord8, getWord8]
    if ei_magic /= "\DELELF" then
        fail "Invalid magic number for ELF"
     else
        return ei_magic

getElfVersion = do
    ei_version <- getWord8
    if ei_version /= 1 then
        fail "Invalid version number for ELF"
     else
        return ei_version

data ElfSectionType
    = SHT_NULL          -- ^ Identifies an empty section header.
    | SHT_PROGBITS      -- ^ Contains information defined by the program
    | SHT_SYMTAB        -- ^ Contains a linker symbol table
    | SHT_STRTAB        -- ^ Contains a string table
    | SHT_RELA          -- ^ Contains "Rela" type relocation entries
    | SHT_HASH          -- ^ Contains a symbol hash table
    | SHT_DYNAMIC       -- ^ Contains dynamic linking tables
    | SHT_NOTE          -- ^ Contains note information
    | SHT_NOBITS        -- ^ Contains uninitialized space; does not occupy any space in the file
    | SHT_REL           -- ^ Contains "Rel" type relocation entries
    | SHT_SHLIB         -- ^ Reserved
    | SHT_DYNSYM        -- ^ Contains a dynamic loader symbol table
    | SHT_EXT Word32    -- ^ Processor- or environment-specific type
    deriving (Eq, Show)
getElfSectionType er = liftM getElfSectionType_ $ getWord32 er
    where getElfSectionType_ 0  = SHT_NULL
          getElfSectionType_ 1  = SHT_PROGBITS
          getElfSectionType_ 2  = SHT_SYMTAB
          getElfSectionType_ 3  = SHT_STRTAB
          getElfSectionType_ 4  = SHT_RELA
          getElfSectionType_ 5  = SHT_HASH
          getElfSectionType_ 6  = SHT_DYNAMIC
          getElfSectionType_ 7  = SHT_NOTE
          getElfSectionType_ 8  = SHT_NOBITS
          getElfSectionType_ 9  = SHT_REL
          getElfSectionType_ 10 = SHT_SHLIB
          getElfSectionType_ 11 = SHT_DYNSYM
          getElfSectionType_ n  = SHT_EXT n

data ElfSectionFlags
    = SHF_WRITE     -- ^ Section contains writable data
    | SHF_ALLOC     -- ^ Section is allocated in memory image of program
    | SHF_EXECINSTR -- ^ Section contains executable instructions
    | SHF_EXT Int   -- ^ Processor- or environment-specific flag
    deriving (Eq, Show)
getElfSectionFlags 0 word = []
getElfSectionFlags 1 word | testBit word 0     = SHF_WRITE     : getElfSectionFlags 0 word
getElfSectionFlags 2 word | testBit word 1     = SHF_ALLOC     : getElfSectionFlags 1 word
getElfSectionFlags 3 word | testBit word 2     = SHF_EXECINSTR : getElfSectionFlags 2 word
getElfSectionFlags n word | testBit word (n-1) = SHF_EXT (n-1) : getElfSectionFlags (n-1) word
getElfSectionFlags n word = getElfSectionFlags (n-1) word
getElfSectionFlags32 = liftM (getElfSectionFlags 32) . getWord32 
getElfSectionFlags64 = liftM (getElfSectionFlags 64) . getWord64
    
data ElfClass
    = ELFCLASS32 -- ^ 32-bit ELF format
    | ELFCLASS64 -- ^ 64-bit ELF format
    deriving (Eq, Show)
getElfClass = getWord8 >>= getElfClass_
    where getElfClass_ 1 = return ELFCLASS32
          getElfClass_ 2 = return ELFCLASS64
          getElfClass_ _ = fail "Invalid ELF class"

data ElfData
    = ELFDATA2LSB -- ^ Little-endian ELF format
    | ELFDATA2MSB -- ^ Big-endian ELF format
    deriving (Eq, Show)
getElfData = getWord8 >>= getElfData_
    where getElfData_ 1 = return ELFDATA2LSB
          getElfData_ 2 = return ELFDATA2MSB
          getElfData_ _ = fail "Invalid ELF data"

data ElfOSABI
    = ELFOSABI_SYSV       -- ^ No extensions or unspecified
    | ELFOSABI_HPUX       -- ^ Hewlett-Packard HP-UX
    | ELFOSABI_NETBSD     -- ^ NetBSD
    | ELFOSABI_LINUX      -- ^ Linux
    | ELFOSABI_SOLARIS    -- ^ Sun Solaris
    | ELFOSABI_AIX        -- ^ AIX
    | ELFOSABI_IRIX       -- ^ IRIX
    | ELFOSABI_FREEBSD    -- ^ FreeBSD
    | ELFOSABI_TRU64      -- ^ Compaq TRU64 UNIX
    | ELFOSABI_MODESTO    -- ^ Novell Modesto
    | ELFOSABI_OPENBSD    -- ^ Open BSD
    | ELFOSABI_OPENVMS    -- ^ Open VMS
    | ELFOSABI_NSK        -- ^ Hewlett-Packard Non-Stop Kernel
    | ELFOSABI_AROS       -- ^ Amiga Research OS
    | ELFOSABI_ARM        -- ^ ARM
    | ELFOSABI_STANDALONE -- ^ Standalone (embedded) application
    | ELFOSABI_EXT Word8  -- ^ Other
    deriving (Eq, Show)
getElfOsabi = liftM getElfOsabi_ getWord8
    where getElfOsabi_ 0   = ELFOSABI_SYSV
          getElfOsabi_ 1   = ELFOSABI_HPUX
          getElfOsabi_ 2   = ELFOSABI_NETBSD
          getElfOsabi_ 3   = ELFOSABI_LINUX
          getElfOsabi_ 6   = ELFOSABI_SOLARIS
          getElfOsabi_ 7   = ELFOSABI_AIX
          getElfOsabi_ 8   = ELFOSABI_IRIX
          getElfOsabi_ 9   = ELFOSABI_FREEBSD
          getElfOsabi_ 10  = ELFOSABI_TRU64
          getElfOsabi_ 11  = ELFOSABI_MODESTO
          getElfOsabi_ 12  = ELFOSABI_OPENBSD
          getElfOsabi_ 13  = ELFOSABI_OPENVMS
          getElfOsabi_ 14  = ELFOSABI_NSK
          getElfOsabi_ 15  = ELFOSABI_AROS
          getElfOsabi_ 97  = ELFOSABI_ARM
          getElfOsabi_ 255 = ELFOSABI_STANDALONE
          getElfOsabi_ n   = ELFOSABI_EXT n

data ElfType
    = ET_NONE       -- ^ Unspecified type
    | ET_REL        -- ^ Relocatable object file
    | ET_EXEC       -- ^ Executable object file
    | ET_DYN        -- ^ Shared object file
    | ET_CORE       -- ^ Core dump object file
    | ET_EXT Word16 -- ^ Other
    deriving (Eq, Show)
getElfType = liftM getElfType_ . getWord16
    where getElfType_ 0 = ET_NONE
          getElfType_ 1 = ET_REL
          getElfType_ 2 = ET_EXEC
          getElfType_ 3 = ET_DYN
          getElfType_ 4 = ET_CORE
          getElfType_ n = ET_EXT n

data ElfMachine
    = EM_NONE        -- ^ No machine
    | EM_M32         -- ^ AT&T WE 32100
    | EM_SPARC       -- ^ SPARC
    | EM_386         -- ^ Intel 80386
    | EM_68K         -- ^ Motorola 68000
    | EM_88K         -- ^ Motorola 88000
    | EM_486         -- ^ Intel i486 (DO NOT USE THIS ONE)
    | EM_860         -- ^ Intel 80860
    | EM_MIPS        -- ^ MIPS I Architecture
    | EM_S370        -- ^ IBM System/370 Processor
    | EM_MIPS_RS3_LE -- ^ MIPS RS3000 Little-endian
    | EM_SPARC64     -- ^ SPARC 64-bit
    | EM_PARISC      -- ^ Hewlett-Packard PA-RISC
    | EM_VPP500      -- ^ Fujitsu VPP500
    | EM_SPARC32PLUS -- ^ Enhanced instruction set SPARC
    | EM_960         -- ^ Intel 80960
    | EM_PPC         -- ^ PowerPC
    | EM_PPC64       -- ^ 64-bit PowerPC
    | EM_S390        -- ^ IBM System/390 Processor
    | EM_SPU         -- ^ Cell SPU
    | EM_V800        -- ^ NEC V800
    | EM_FR20        -- ^ Fujitsu FR20
    | EM_RH32        -- ^ TRW RH-32
    | EM_RCE         -- ^ Motorola RCE
    | EM_ARM         -- ^ Advanced RISC Machines ARM
    | EM_ALPHA       -- ^ Digital Alpha
    | EM_SH          -- ^ Hitachi SH
    | EM_SPARCV9     -- ^ SPARC Version 9
    | EM_TRICORE     -- ^ Siemens TriCore embedded processor
    | EM_ARC         -- ^ Argonaut RISC Core, Argonaut Technologies Inc.
    | EM_H8_300      -- ^ Hitachi H8/300
    | EM_H8_300H     -- ^ Hitachi H8/300H
    | EM_H8S         -- ^ Hitachi H8S
    | EM_H8_500      -- ^ Hitachi H8/500
    | EM_IA_64       -- ^ Intel IA-64 processor architecture
    | EM_MIPS_X      -- ^ Stanford MIPS-X
    | EM_COLDFIRE    -- ^ Motorola ColdFire
    | EM_68HC12      -- ^ Motorola M68HC12
    | EM_MMA         -- ^ Fujitsu MMA Multimedia Accelerator
    | EM_PCP         -- ^ Siemens PCP
    | EM_NCPU        -- ^ Sony nCPU embedded RISC processor
    | EM_NDR1        -- ^ Denso NDR1 microprocessor
    | EM_STARCORE    -- ^ Motorola Star*Core processor
    | EM_ME16        -- ^ Toyota ME16 processor
    | EM_ST100       -- ^ STMicroelectronics ST100 processor
    | EM_TINYJ       -- ^ Advanced Logic Corp. TinyJ embedded processor family
    | EM_X86_64      -- ^ AMD x86-64 architecture
    | EM_PDSP        -- ^ Sony DSP Processor
    | EM_FX66        -- ^ Siemens FX66 microcontroller
    | EM_ST9PLUS     -- ^ STMicroelectronics ST9+ 8/16 bit microcontroller
    | EM_ST7         -- ^ STMicroelectronics ST7 8-bit microcontroller
    | EM_68HC16      -- ^ Motorola MC68HC16 Microcontroller
    | EM_68HC11      -- ^ Motorola MC68HC11 Microcontroller
    | EM_68HC08      -- ^ Motorola MC68HC08 Microcontroller
    | EM_68HC05      -- ^ Motorola MC68HC05 Microcontroller
    | EM_SVX         -- ^ Silicon Graphics SVx
    | EM_ST19        -- ^ STMicroelectronics ST19 8-bit microcontroller
    | EM_VAX         -- ^ Digital VAX
    | EM_CRIS        -- ^ Axis Communications 32-bit embedded processor
    | EM_JAVELIN     -- ^ Infineon Technologies 32-bit embedded processor
    | EM_FIREPATH    -- ^ Element 14 64-bit DSP Processor
    | EM_ZSP         -- ^ LSI Logic 16-bit DSP Processor
    | EM_MMIX        -- ^ Donald Knuth's educational 64-bit processor
    | EM_HUANY       -- ^ Harvard University machine-independent object files
    | EM_PRISM       -- ^ SiTera Prism
    | EM_AVR         -- ^ Atmel AVR 8-bit microcontroller
    | EM_FR30        -- ^ Fujitsu FR30
    | EM_D10V        -- ^ Mitsubishi D10V
    | EM_D30V        -- ^ Mitsubishi D30V
    | EM_V850        -- ^ NEC v850
    | EM_M32R        -- ^ Mitsubishi M32R
    | EM_MN10300     -- ^ Matsushita MN10300
    | EM_MN10200     -- ^ Matsushita MN10200
    | EM_PJ          -- ^ picoJava
    | EM_OPENRISC    -- ^ OpenRISC 32-bit embedded processor
    | EM_ARC_A5      -- ^ ARC Cores Tangent-A5
    | EM_XTENSA      -- ^ Tensilica Xtensa Architecture
    | EM_VIDEOCORE   -- ^ Alphamosaic VideoCore processor
    | EM_TMM_GPP     -- ^ Thompson Multimedia General Purpose Processor
    | EM_NS32K       -- ^ National Semiconductor 32000 series
    | EM_TPC         -- ^ Tenor Network TPC processor
    | EM_SNP1K       -- ^ Trebia SNP 1000 processor
    | EM_ST200       -- ^ STMicroelectronics (www.st.com) ST200 microcontroller
    | EM_IP2K        -- ^ Ubicom IP2xxx microcontroller family
    | EM_MAX         -- ^ MAX Processor
    | EM_CR          -- ^ National Semiconductor CompactRISC microprocessor
    | EM_F2MC16      -- ^ Fujitsu F2MC16
    | EM_MSP430      -- ^ Texas Instruments embedded microcontroller msp430
    | EM_BLACKFIN    -- ^ Analog Devices Blackfin (DSP) processor
    | EM_SE_C33      -- ^ S1C33 Family of Seiko Epson processors
    | EM_SEP         -- ^ Sharp embedded microprocessor
    | EM_ARCA        -- ^ Arca RISC Microprocessor
    | EM_UNICORE     -- ^ Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    | EM_EXT Word16  -- ^ Other
    deriving (Eq, Show)
getElfMachine = liftM getElfMachine_ . getWord16
    where getElfMachine_ 0   = EM_NONE
          getElfMachine_ 1   = EM_M32
          getElfMachine_ 2   = EM_SPARC
          getElfMachine_ 3   = EM_386
          getElfMachine_ 4   = EM_68K
          getElfMachine_ 5   = EM_88K
          getElfMachine_ 6   = EM_486
          getElfMachine_ 7   = EM_860
          getElfMachine_ 8   = EM_MIPS
          getElfMachine_ 9   = EM_S370
          getElfMachine_ 10  = EM_MIPS_RS3_LE
          getElfMachine_ 11  = EM_SPARC64
          getElfMachine_ 15  = EM_PARISC
          getElfMachine_ 17  = EM_VPP500
          getElfMachine_ 18  = EM_SPARC32PLUS
          getElfMachine_ 19  = EM_960
          getElfMachine_ 20  = EM_PPC
          getElfMachine_ 21  = EM_PPC64
          getElfMachine_ 22  = EM_S390
          getElfMachine_ 23  = EM_SPU
          getElfMachine_ 36  = EM_V800
          getElfMachine_ 37  = EM_FR20
          getElfMachine_ 38  = EM_RH32
          getElfMachine_ 39  = EM_RCE
          getElfMachine_ 40  = EM_ARM
          getElfMachine_ 41  = EM_ALPHA
          getElfMachine_ 42  = EM_SH
          getElfMachine_ 43  = EM_SPARCV9
          getElfMachine_ 44  = EM_TRICORE
          getElfMachine_ 45  = EM_ARC
          getElfMachine_ 46  = EM_H8_300
          getElfMachine_ 47  = EM_H8_300H
          getElfMachine_ 48  = EM_H8S
          getElfMachine_ 49  = EM_H8_500
          getElfMachine_ 50  = EM_IA_64
          getElfMachine_ 51  = EM_MIPS_X
          getElfMachine_ 52  = EM_COLDFIRE
          getElfMachine_ 53  = EM_68HC12
          getElfMachine_ 54  = EM_MMA
          getElfMachine_ 55  = EM_PCP
          getElfMachine_ 56  = EM_NCPU
          getElfMachine_ 57  = EM_NDR1
          getElfMachine_ 58  = EM_STARCORE
          getElfMachine_ 59  = EM_ME16
          getElfMachine_ 60  = EM_ST100
          getElfMachine_ 61  = EM_TINYJ
          getElfMachine_ 62  = EM_X86_64
          getElfMachine_ 63  = EM_PDSP
          getElfMachine_ 66  = EM_FX66
          getElfMachine_ 67  = EM_ST9PLUS
          getElfMachine_ 68  = EM_ST7
          getElfMachine_ 69  = EM_68HC16
          getElfMachine_ 70  = EM_68HC11
          getElfMachine_ 71  = EM_68HC08
          getElfMachine_ 72  = EM_68HC05
          getElfMachine_ 73  = EM_SVX
          getElfMachine_ 74  = EM_ST19
          getElfMachine_ 75  = EM_VAX
          getElfMachine_ 76  = EM_CRIS
          getElfMachine_ 77  = EM_JAVELIN
          getElfMachine_ 78  = EM_FIREPATH
          getElfMachine_ 79  = EM_ZSP
          getElfMachine_ 80  = EM_MMIX
          getElfMachine_ 81  = EM_HUANY
          getElfMachine_ 82  = EM_PRISM
          getElfMachine_ 83  = EM_AVR
          getElfMachine_ 84  = EM_FR30
          getElfMachine_ 85  = EM_D10V
          getElfMachine_ 86  = EM_D30V
          getElfMachine_ 87  = EM_V850
          getElfMachine_ 88  = EM_M32R
          getElfMachine_ 89  = EM_MN10300
          getElfMachine_ 90  = EM_MN10200
          getElfMachine_ 91  = EM_PJ
          getElfMachine_ 92  = EM_OPENRISC
          getElfMachine_ 93  = EM_ARC_A5
          getElfMachine_ 94  = EM_XTENSA
          getElfMachine_ 95  = EM_VIDEOCORE
          getElfMachine_ 96  = EM_TMM_GPP
          getElfMachine_ 97  = EM_NS32K
          getElfMachine_ 98  = EM_TPC
          getElfMachine_ 99  = EM_SNP1K
          getElfMachine_ 100 = EM_ST200
          getElfMachine_ 101 = EM_IP2K
          getElfMachine_ 102 = EM_MAX
          getElfMachine_ 103 = EM_CR
          getElfMachine_ 104 = EM_F2MC16
          getElfMachine_ 105 = EM_MSP430
          getElfMachine_ 106 = EM_BLACKFIN
          getElfMachine_ 107 = EM_SE_C33
          getElfMachine_ 108 = EM_SEP
          getElfMachine_ 109 = EM_ARCA
          getElfMachine_ 110 = EM_UNICORE
          getElfMachine_ n   = EM_EXT n

getElf_Shdr_OffsetSize :: ElfClass -> ElfReader -> Get (Word64, Word64)
getElf_Shdr_OffsetSize ei_class er =
    case ei_class of
        ELFCLASS32 -> do
            skip 16
            sh_offset <- liftM fromIntegral $ getWord32 er
            sh_size   <- liftM fromIntegral $ getWord32 er
            return (sh_offset, sh_size)
        ELFCLASS64 -> do
            skip 24
            sh_offset <- getWord64 er
            sh_size   <- getWord64 er
            return (sh_offset, sh_size)

getElf_Shdr :: ElfClass -> ElfReader -> B.ByteString -> B.ByteString -> Get ElfSection
getElf_Shdr ei_class er elf_file string_section =
    case ei_class of
        ELFCLASS32 -> do
            sh_name      <- getWord32 er
            sh_type      <- getElfSectionType er
            sh_flags     <- getElfSectionFlags32 er
            sh_addr      <- getWord32 er
            sh_offset    <- getWord32 er
            sh_size      <- getWord32 er
            sh_link      <- getWord32 er
            sh_info      <- getWord32 er
            sh_addralign <- getWord32 er
            sh_entsize   <- getWord32 er
            return ElfSection
                { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
                , elfSectionType      = sh_type
                , elfSectionFlags     = sh_flags
                , elfSectionAddr      = fromIntegral sh_addr
                , elfSectionSize      = fromIntegral sh_size
                , elfSectionLink      = sh_link
                , elfSectionInfo      = sh_info
                , elfSectionAddrAlign = fromIntegral sh_addralign
                , elfSectionEntSize   = fromIntegral sh_entsize
                , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
                }
        ELFCLASS64 -> do
            sh_name      <- getWord32 er
            sh_type      <- getElfSectionType er
            sh_flags     <- getElfSectionFlags64 er
            sh_addr      <- getWord64 er
            sh_offset    <- getWord64 er
            sh_size      <- getWord64 er
            sh_link      <- getWord32 er
            sh_info      <- getWord32 er
            sh_addralign <- getWord64 er
            sh_entsize   <- getWord64 er
            return ElfSection
                { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
                , elfSectionType      = sh_type
                , elfSectionFlags     = sh_flags
                , elfSectionAddr      = sh_addr
                , elfSectionSize      = sh_size
                , elfSectionLink      = sh_link
                , elfSectionInfo      = sh_info
                , elfSectionAddrAlign = sh_addralign
                , elfSectionEntSize   = sh_entsize
                , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
                }

data TableInfo = TableInfo { tableOffset :: Int, entrySize :: Int, entryNum :: Int }

getElf_Ehdr :: Get (Elf, TableInfo, TableInfo, Word16)
getElf_Ehdr = do
    ei_magic    <- getElfMagic
    ei_class    <- getElfClass
    ei_data     <- getElfData
    ei_version  <- liftM fromIntegral getElfVersion
    ei_osabi    <- getElfOsabi
    ei_abiver   <- liftM fromIntegral getWord8
    skip 7
    er          <- return $ elfReader ei_data
    case ei_class of
        ELFCLASS32 -> do
            e_type      <- getElfType er
            e_machine   <- getElfMachine er
            e_version   <- getWord32 er
            e_entry     <- liftM fromIntegral $ getWord32 er
            e_phoff     <- getWord32 er
            e_shoff     <- liftM fromIntegral $ getWord32 er
            e_flags     <- getWord32 er
            e_ehsize    <- getWord16 er
            e_phentsize <- getWord16 er
            e_phnum     <- getWord16 er
            e_shentsize <- getWord16 er
            e_shnum     <- getWord16 er
            e_shstrndx  <- getWord16 er
            return (Elf { elfClass      = ei_class
                        , elfData       = ei_data
                        , elfVersion    = ei_version
                        , elfOSABI      = ei_osabi
                        , elfABIVersion = ei_abiver
                        , elfType       = e_type
                        , elfMachine    = e_machine
                        , elfEntry      = e_entry
                        , elfSections   = []
                        , elfSegments   = [] }
                   , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
                   , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
                   , e_shstrndx)
        ELFCLASS64 -> do
            e_type      <- getElfType er
            e_machine   <- getElfMachine er
            e_version   <- getWord32 er
            e_entry     <- getWord64 er
            e_phoff     <- getWord64 er
            e_shoff     <- getWord64 er
            e_flags     <- getWord32 er
            e_ehsize    <- getWord16 er
            e_phentsize <- getWord16 er
            e_phnum     <- getWord16 er
            e_shentsize <- getWord16 er
            e_shnum     <- getWord16 er
            e_shstrndx  <- getWord16 er
            return (Elf { elfClass      = ei_class
                        , elfData       = ei_data
                        , elfVersion    = ei_version
                        , elfOSABI      = ei_osabi
                        , elfABIVersion = ei_abiver
                        , elfType       = e_type
                        , elfMachine    = e_machine
                        , elfEntry      = e_entry
                        , elfSections   = []
                        , elfSegments   = [] }
                   , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
                   , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
                   , e_shstrndx)

data ElfReader = ElfReader
    { getWord16 :: Get Word16
    , getWord32 :: Get Word32
    , getWord64 :: Get Word64
    }
elfReader ELFDATA2LSB = ElfReader { getWord16 = getWord16le, getWord32 = getWord32le, getWord64 = getWord64le }
elfReader ELFDATA2MSB = ElfReader { getWord16 = getWord16be, getWord32 = getWord32be, getWord64 = getWord64be }

divide :: B.ByteString -> Int -> Int -> [B.ByteString]
divide bs s 0 = []
divide bs s n = let (x,y) = B.splitAt s bs in x : divide y s (n-1)

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have their
-- fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Elf
parseElf b =
    let ph                                             = table segTab
        sh                                             = table secTab
        (shstroff, shstrsize)                          = parseEntry getElf_Shdr_OffsetSize $ head $ drop (fromIntegral e_shstrndx) sh
        sh_str                                         = B.take (fromIntegral shstrsize) $ B.drop (fromIntegral shstroff) b
        segments                                       = map (parseEntry (\c r -> parseElfSegmentEntry c r b)) ph
        sections                                       = map (parseEntry (\c r -> getElf_Shdr c r b sh_str)) sh
    in e { elfSections = sections, elfSegments = segments }

  where table i                         = divide (B.drop (tableOffset i) b) (entrySize i) (entryNum i)
        parseEntry p x                  = runGet (p (elfClass e) (elfReader (elfData e))) (L.fromChunks [x])
        (e, segTab, secTab, e_shstrndx) = runGet getElf_Ehdr $ L.fromChunks [b]


data ElfSegment = ElfSegment
  { elfSegmentType      :: ElfSegmentType   -- ^ Segment type
  , elfSegmentFlags     :: [ElfSegmentFlag] -- ^ Segment flags
  , elfSegmentVirtAddr  :: Word64           -- ^ Virtual address for the segment
  , elfSegmentPhysAddr  :: Word64           -- ^ Physical address for the segment
  , elfSegmentAlign     :: Word64           -- ^ Segment alignment
  , elfSegmentData      :: B.ByteString     -- ^ Data for the segment
  , elfSegmentMemSize   :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
  } deriving (Eq,Show)

-- | Segment Types.
data ElfSegmentType
  = PT_NULL         -- ^ Unused entry
  | PT_LOAD         -- ^ Loadable segment
  | PT_DYNAMIC      -- ^ Dynamic linking tables
  | PT_INTERP       -- ^ Program interpreter path name
  | PT_NOTE         -- ^ Note sectionks
  | PT_SHLIB        -- ^ Reserved
  | PT_PHDR         -- ^ Program header table
  | PT_Other Word32 -- ^ Some other type
    deriving (Eq,Show)

parseElfSegmentType :: Word32 -> ElfSegmentType
parseElfSegmentType x =
  case x of
    0 -> PT_NULL
    1 -> PT_LOAD
    2 -> PT_DYNAMIC
    3 -> PT_INTERP
    4 -> PT_NOTE
    5 -> PT_SHLIB
    6 -> PT_PHDR
    _ -> PT_Other x


parseElfSegmentEntry :: ElfClass -> ElfReader -> B.ByteString -> Get ElfSegment
parseElfSegmentEntry elf_class er elf_file = case elf_class of
  ELFCLASS64 -> do
     p_type   <- parseElfSegmentType  `fmap` getWord32 er
     p_flags  <- parseElfSegmentFlags `fmap` getWord32 er
     p_offset <- getWord64 er
     p_vaddr  <- getWord64 er
     p_paddr  <- getWord64 er
     p_filesz <- getWord64 er
     p_memsz  <- getWord64 er
     p_align  <- getWord64 er
     return ElfSegment
       { elfSegmentType     = p_type
       , elfSegmentFlags    = p_flags
       , elfSegmentVirtAddr = p_vaddr
       , elfSegmentPhysAddr = p_paddr
       , elfSegmentAlign    = p_align
       , elfSegmentData     = B.take (fromIntegral p_filesz) $ B.drop (fromIntegral p_offset) elf_file
       , elfSegmentMemSize  = p_memsz
       }

  ELFCLASS32 -> do
     p_type   <- parseElfSegmentType  `fmap` getWord32 er
     p_offset <- fromIntegral `fmap` getWord32 er
     p_vaddr  <- fromIntegral `fmap` getWord32 er
     p_paddr  <- fromIntegral `fmap` getWord32 er
     p_filesz <- fromIntegral `fmap` getWord32 er
     p_memsz  <- fromIntegral `fmap` getWord32 er
     p_flags  <- parseElfSegmentFlags `fmap` getWord32 er
     p_align  <- fromIntegral `fmap` getWord32 er
     return ElfSegment
       { elfSegmentType     = p_type
       , elfSegmentFlags    = p_flags
       , elfSegmentVirtAddr = p_vaddr
       , elfSegmentPhysAddr = p_paddr
       , elfSegmentAlign    = p_align
       , elfSegmentData     = B.take (fromIntegral p_filesz) $ B.drop (fromIntegral p_offset) elf_file
       , elfSegmentMemSize  = p_memsz
       }

data ElfSegmentFlag
  = PF_X        -- ^ Execute permission
  | PF_W        -- ^ Write permission
  | PF_R        -- ^ Read permission
  | PF_Ext Int  -- ^ Some other flag, the Int is the bit number for the flag.
    deriving (Eq,Show)

parseElfSegmentFlags :: Word32 -> [ElfSegmentFlag]
parseElfSegmentFlags word = [ cvt bit | bit <- [ 0 .. 31 ], testBit word bit ]
  where cvt 0 = PF_X
        cvt 1 = PF_W
        cvt 2 = PF_R
        cvt n = PF_Ext n

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file. Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry = EST
    { steName             :: (Word32,Maybe B.ByteString)
    , steEnclosingSection :: Maybe ElfSection -- ^ Section from steIndex
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: Word64
    , steSize             :: Word64
    } deriving (Eq, Show)

-- | Parse the symbol table section into a list of symbol table entries. If
-- no symbol table is found then an empty list is returned.
-- This function does not consult flags to look for SHT_STRTAB (when naming symbols),
-- it just looks for particular sections of ".strtab" and ".shstrtab".
parseSymbolTables :: Elf -> [[ElfSymbolTableEntry]]
parseSymbolTables e =
    let secs = symbolTableSections e
    in map (getSymbolTableEntries e) secs

-- | Assumes the given section is a symbol table, type SHT_SYMTAB
-- (guaranteed by parseSymbolTables).
getSymbolTableEntries :: Elf -> ElfSection -> [ElfSymbolTableEntry]
getSymbolTableEntries e s =
    let link   = elfSectionLink s
        strtab = lookup (fromIntegral link) (zip [0..] (elfSections e))
    in runGetMany (getSymbolTableEntry e strtab) (L.fromChunks [elfSectionData s])

-- | Use the symbol offset and size to extract its definition
-- (in the form of a ByteString).
-- If the size is zero, or the offset larger than the 'elfSectionData',
-- then 'Nothing' is returned.
findSymbolDefinition :: ElfSymbolTableEntry -> Maybe B.ByteString
findSymbolDefinition e =
    let enclosingData = fmap elfSectionData (steEnclosingSection e)
        start = fromIntegral (steValue e)
        len = fromIntegral (steSize e)
        def = fmap (B.take len . B.drop start) enclosingData
    in if def == Just B.empty then Nothing else def

runGetMany :: Get a -> L.ByteString -> [a]
runGetMany g bs
    | L.length bs == 0 = []
    | otherwise        = let (v,bs',_) = runGetState g bs 0 in v: runGetMany g bs'

symbolTableSections :: Elf -> [ElfSection]
symbolTableSections e = filter ((== SHT_SYMTAB) . elfSectionType) (elfSections e)

-- | Gets a single entry from the symbol table, use with runGetMany.
getSymbolTableEntry :: Elf -> Maybe ElfSection -> Get ElfSymbolTableEntry
getSymbolTableEntry e strtlb =
    if elfClass e == ELFCLASS32 then getSymbolTableEntry32 else getSymbolTableEntry64
  where
  strs = fromMaybe B.empty (fmap elfSectionData strtlb)
  er = elfReader (elfData e)
  getSymbolTableEntry32 = do
    nameIdx <- liftM fromIntegral (getWord32 er)
    value <- liftM fromIntegral (getWord32 er)
    size  <- liftM fromIntegral (getWord32 er)
    info  <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx value size
  getSymbolTableEntry64 = do
    nameIdx <- liftM fromIntegral (getWord32 er)
    info <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    symVal <- getWord64 er
    size <- getWord64 er
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx symVal size

sectionByIndex :: Elf -> ElfSectionIndex -> Maybe ElfSection
sectionByIndex e (SHNIndex i) = lookup i . zip [1..] $ (elfSections e)
sectionByIndex _ _ = Nothing

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
    let t = fromIntegral $ i .&. 0x0F
        b = fromIntegral $ (i .&. 0xF0) `shiftR` 4
    in (toEnum t, toEnum b)

data ElfSymbolBinding
    = STBLocal
    | STBGlobal
    | STBWeak
    | STBLoOS
    | STBHiOS
    | STBLoProc
    | STBHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolBinding where
    fromEnum STBLocal  = 0
    fromEnum STBGlobal = 1
    fromEnum STBWeak   = 2
    fromEnum STBLoOS   = 10
    fromEnum STBHiOS   = 12
    fromEnum STBLoProc = 13
    fromEnum STBHiProc = 15
    toEnum  0 = STBLocal
    toEnum  1 = STBGlobal
    toEnum  2 = STBWeak
    toEnum 10 = STBLoOS
    toEnum 12 = STBHiOS
    toEnum 13 = STBLoProc
    toEnum 15 = STBHiProc

data ElfSymbolType
    = STTNoType
    | STTObject
    | STTFunc
    | STTSection
    | STTFile
    | STTCommon
    | STTTLS
    | STTLoOS
    | STTHiOS
    | STTLoProc
    | STTHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolType where
    fromEnum STTNoType  = 0
    fromEnum STTObject  = 1
    fromEnum STTFunc    = 2
    fromEnum STTSection = 3
    fromEnum STTFile    = 4
    fromEnum STTCommon  = 5
    fromEnum STTTLS     = 6
    fromEnum STTLoOS    = 10
    fromEnum STTHiOS    = 12
    fromEnum STTLoProc  = 13
    fromEnum STTHiProc  = 15
    toEnum  0 = STTNoType
    toEnum  1 = STTObject
    toEnum  2 = STTFunc
    toEnum  3 = STTSection
    toEnum  4 = STTFile
    toEnum  5 = STTCommon
    toEnum  6 = STTTLS
    toEnum 10 = STTLoOS
    toEnum 12 = STTHiOS
    toEnum 13 = STTLoProc
    toEnum 15 = STTHiProc

data ElfSectionIndex
    = SHNUndef
    | SHNLoProc
    | SHNCustomProc Word64
    | SHNHiProc
    | SHNLoOS
    | SHNCustomOS Word64
    | SHNHiOS
    | SHNAbs
    | SHNCommon
    | SHNIndex Word64
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSectionIndex where
    fromEnum SHNUndef = 0
    fromEnum SHNLoProc = 0xFF00
    fromEnum SHNHiProc = 0xFF1F
    fromEnum SHNLoOS   = 0xFF20
    fromEnum SHNHiOS   = 0xFF3F
    fromEnum SHNAbs    = 0xFFF1
    fromEnum SHNCommon = 0xFFF2
    fromEnum (SHNCustomProc x) = fromIntegral x
    fromEnum (SHNCustomOS x) = fromIntegral x
    fromEnum (SHNIndex x) = fromIntegral x
    toEnum 0 = SHNUndef
    toEnum 0xff00 = SHNLoProc
    toEnum 0xFF1F = SHNHiProc
    toEnum 0xFF20 = SHNLoOS
    toEnum 0xFF3F = SHNHiOS
    toEnum 0xFFF1 = SHNAbs
    toEnum 0xFFF2 = SHNCommon
    toEnum x
        | x > fromEnum SHNLoProc && x < fromEnum SHNHiProc = SHNCustomProc (fromIntegral x)
        | x > fromEnum SHNLoOS && x < fromEnum SHNHiOS = SHNCustomOS (fromIntegral x)
        | x < fromEnum SHNLoProc || x > 0xFFFF = SHNIndex (fromIntegral x)
        | otherwise = error "Section index number is in a reserved range but we don't recognize the value from any standard."

-- | Given a section name, extract the ElfSection.
findSectionByName :: String -> Elf -> Maybe ElfSection
findSectionByName name = listToMaybe . filter ((==) name . elfSectionName) . elfSections

-- Get a string from a strtab ByteString.
stringByIndex :: Integral n => n -> B.ByteString -> Maybe B.ByteString
stringByIndex n strtab =
    let str = (B.takeWhile (/=0) . B.drop (fromIntegral n)) strtab
    in if B.length str == 0 then Nothing else Just str


