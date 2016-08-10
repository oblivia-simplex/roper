
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

data ElfSectionFlags
    = SHF_WRITE     -- ^ Section contains writable data
    | SHF_ALLOC     -- ^ Section is allocated in memory image of program
    | SHF_EXECINSTR -- ^ Section contains executable instructions
    | SHF_EXT Int   -- ^ Processor- or environment-specific flag
    deriving (Eq, Show)

data ElfClass
    = ELFCLASS32 -- ^ 32-bit ELF format
    | ELFCLASS64 -- ^ 64-bit ELF format
    deriving (Eq, Show)

data ElfData
    = ELFDATA2LSB -- ^ Little-endian ELF format
    | ELFDATA2MSB -- ^ Big-endian ELF format
    deriving (Eq, Show)

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
data ElfType
    = ET_NONE       -- ^ Unspecified type
    | ET_REL        -- ^ Relocatable object file
    | ET_EXEC       -- ^ Executable object file
    | ET_DYN        -- ^ Shared object file
    | ET_CORE       -- ^ Core dump object file
    | ET_EXT Word16 -- ^ Other
    deriving (Eq, Show)

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

data TableInfo = TableInfo { tableOffset :: Int, entrySize :: Int, entryNum :: Int }

data ElfReader = ElfReader
    { getWord16 :: Get Word16
    , getWord32 :: Get Word32
    , getWord64 :: Get Word64
    }

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

data ElfSegmentFlag
  = PF_X        -- ^ Execute permission
  | PF_W        -- ^ Write permission
  | PF_R        -- ^ Read permission
  | PF_Ext Int  -- ^ Some other flag, the Int is the bit number for the flag.
    deriving (Eq,Show)

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

