import ctypes

"""
The ModuleData Structure is stored in runtime/symtab.go

"""

class ModuleDataGo1_6(ctypes.Structure):
    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr

        typelinks []*_type

        modulename   string
        modulehashes []modulehash

        gcdatamask, gcbssmask bitvector

        next *moduledata
    }"""
    pass


class ModuleDataGo1_7(ctypes.Structure):
    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        typelinks []int32 // offsets from types
        itablinks []*itab

        modulename   string
        modulehashes []modulehash

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        next *moduledata
    }"""
    pass


class ModuleDataGo1_8(ctypes.Structure):
    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        next *moduledata
    }"""
    pass


class ModuleDataGo1_9(ctypes.Structure):
    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        next *moduledata
    }"""
    pass


class ModuleDataGo1_10_15_32(ctypes.Structure):
    """"parse 32-bit Go1.10 through Go1.15"""

    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        hasmain uint8 // 1 if module contains the main function, 0 otherwise

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        bad bool // module failed to load and should be ignored

        next *moduledata
    }"""
    _fields_ = [
        ("pclntable",  ctypes.c_uint32),  # []byte
        ("pclntable_len", ctypes.c_uint32),
        ("pclntable_cap", ctypes.c_uint32),
        ("ftab", ctypes.c_uint32),  # []functab
        ("ftab_len", ctypes.c_uint32),
        ("ftab_cap", ctypes.c_uint32),
        ("filetab", ctypes.c_uint32),  # []uint32
        ("filetab_len", ctypes.c_uint32),
        ("filetab_cap", ctypes.c_uint32),
        ("findfunctab", ctypes.c_uint32),  # uintptr
        ("minpc", ctypes.c_uint32),  # uintptr
        ("maxpc", ctypes.c_uint32),  # uintptr
        ("text", ctypes.c_uint32),  #
        ("etext", ctypes.c_uint32),  # uintptr
        ("noptrdata", ctypes.c_uint32),  # uintptr
        ("enoptrdata", ctypes.c_uint32),  # uintptr
        ("data", ctypes.c_uint32),  # uintptr
        ("edata", ctypes.c_uint32),  # uintptr
        ("bss", ctypes.c_uint32),  # uintptr
        ("ebss", ctypes.c_uint32),  # uintptr
        ("noptrbss", ctypes.c_uint32),  # uintptr
        ("enoptrbss", ctypes.c_uint32),  # uintptr
        ("end", ctypes.c_uint32),  # uintptr
        ("gcdata", ctypes.c_uint32),  # uintptr
        ("gcbss", ctypes.c_uint32),  # uintptr
        ("types", ctypes.c_uint32),  # uintptr
        ("etypes", ctypes.c_uint32),    # uintptr
        ("textsectmap", ctypes.c_uint32),  # []textsect
        ("textsectmap_len", ctypes.c_uint32),
        ("textsectmap_cap", ctypes.c_uint32),
        ("typelinks", ctypes.c_uint32),   # []int32
        ("typelinks_len", ctypes.c_uint32),
        ("typelinks_cap", ctypes.c_uint32),
        ("itablinks", ctypes.c_uint32),  # []*itab
        ("itablinks_len", ctypes.c_uint32),
        ("itablinks_cap", ctypes.c_uint32),
        ("ptab", ctypes.c_uint32),  # []ptabEntry
        ("ptab_len", ctypes.c_uint32),
        ("pluginpath", ctypes.c_uint32),  # string
        ("pkghashes", ctypes.c_uint32),  # []modulehash
        ("pkghashes_len", ctypes.c_uint32),
        ("pkghashes_cap", ctypes.c_uint32),
        ("modulename", ctypes.c_uint32),  # string
        ("modulehashes", ctypes.c_uint32),  # []modulehash
        ("modulehashes_len", ctypes.c_uint32),
        ("modulehashes_cap", ctypes.c_uint32),
        ("hasmain", ctypes.c_uint8),  # uint8
        ("gcdatamask", ctypes.c_uint32),  # bitvector
        ("gcbssmask", ctypes.c_uint32),  # bitvector
        ("typemap", ctypes.c_uint32),  # map[typeOff]*_type
        ("bad", ctypes.c_bool),
        ("next", ctypes.c_uint32) # next * moduledata
    ]

class ModuleDataGo1_10_15_64(ctypes.Structure):
    """parse 64-bit Go1.10 through Go1.15"""

    """type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        hasmain uint8 // 1 if module contains the main function, 0 otherwise

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        bad bool // module failed to load and should be ignored

        next *moduledata
    }"""

    _fields_ = [
        ("pclntable",  ctypes.c_uint64),  # []byte
        ("pclntable_len", ctypes.c_uint64),
        ("pclntable_cap", ctypes.c_uint64),
        ("ftab", ctypes.c_uint64),  # []functab
        ("ftab_len", ctypes.c_uint64),
        ("ftab_cap", ctypes.c_uint64),
        ("filetab", ctypes.c_uint64),  # []uint32
        ("filetab_len", ctypes.c_uint64),
        ("filetab_cap", ctypes.c_uint64),
        ("findfunctab", ctypes.c_uint64),  # uintptr
        ("minpc", ctypes.c_uint64),  # uintptr
        ("maxpc", ctypes.c_uint64),  # uintptr
        ("text", ctypes.c_uint64),  #
        ("etext", ctypes.c_uint64),  # uintptr
        ("noptrdata", ctypes.c_uint64),  # uintptr
        ("enoptrdata", ctypes.c_uint64),  # uintptr
        ("data", ctypes.c_uint64),  # uintptr
        ("edata", ctypes.c_uint64),  # uintptr
        ("bss", ctypes.c_uint64),  # uintptr
        ("ebss", ctypes.c_uint64),  # uintptr
        ("noptrbss", ctypes.c_uint64),  # uintptr
        ("enoptrbss", ctypes.c_uint64),  # uintptr
        ("end", ctypes.c_uint64),  # uintptr
        ("gcdata", ctypes.c_uint64),  # uintptr
        ("gcbss", ctypes.c_uint64),  # uintptr
        ("types", ctypes.c_uint64),  # uintptr
        ("etypes", ctypes.c_uint64),    # uintptr
        ("textsectmap", ctypes.c_uint64),  # []textsect
        ("textsectmap_len", ctypes.c_uint64),
        ("textsectmap_cap", ctypes.c_uint64),
        ("typelinks", ctypes.c_uint64),   # []int32
        ("typelinks_len", ctypes.c_uint64),
        ("typelinks_cap", ctypes.c_uint64),
        ("itablinks", ctypes.c_uint64),  # []*itab
        ("itablinks_len", ctypes.c_uint64),
        ("itablinks_cap", ctypes.c_uint64),
        ("ptab", ctypes.c_uint64),  # []ptabEntry
        ("ptab_len", ctypes.c_uint64),
        ("pluginpath", ctypes.c_uint64),  # string
        ("pkghashes", ctypes.c_uint64),  # []modulehash
        ("pkghashes_len", ctypes.c_uint64),
        ("pkghashes_cap", ctypes.c_uint64),
        ("modulename", ctypes.c_uint64),  # string
        ("modulehashes", ctypes.c_uint64),  # []modulehash
        ("modulehashes_len", ctypes.c_uint64),
        ("modulehashes_cap", ctypes.c_uint64),
        ("hasmain", ctypes.c_uint8),  # uint8
        ("gcdatamask", ctypes.c_uint64),  # bitvector
        ("gcbssmask", ctypes.c_uint64),  # bitvector
        ("typemap", ctypes.c_uint64),  # map[typeOff]*_type
        ("bad", ctypes.c_bool),
        ("next", ctypes.c_uint64) # next * moduledata
    ]

