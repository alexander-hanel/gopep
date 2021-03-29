"""
Author: Alexander Hanel
Version: 1.3
Purpose: go portable executable parser
Requirements: Python3+ & Pefile
Updates:
    * Version 1.1 - fixed bug in file tab structure parsing and other fixes
    * Version 1.2 - fixed bug in coff string table parser
    * Version 1.3 - Go function API logger added go_logger.py

"""
import argparse
import pefile
import struct
import ctypes
import glob
import binascii
import json
import os
from hashlib import md5
from difflib import SequenceMatcher
from module_data import *
from poor_cluster_logic import *


IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Go Version Constants
VERSION_1_16 = b"\x67\x6f\x31\x2e\x31\x36"
VERSION_1_15 = b"\x67\x6f\x31\x2e\x31\x35"
VERSION_1_14 = b"\x67\x6f\x31\x2e\x31\x34"
VERSION_1_13 = b"\x67\x6f\x31\x2e\x31\x33"
VERSION_1_12 = b"\x67\x6f\x31\x2e\x31\x32"
VERSION_1_11 = b"\x67\x6f\x31\x2e\x31\x31"
VERSION_1_10 = b"\x67\x6f\x31\x2e\x31\x30"
VERSION_1_9 = b"\x67\x6f\x31\x2e\x39"
VERSION_1_8 = b"\x67\x6f\x31\x2e\x38"
VERSION_1_7 = b"\x67\x6f\x31\x2e\x37"
VERSION_1_6 = b"\x67\x6f\x31\x2e\x36"
VERSION_1_5 = b"\x67\x6f\x31\x2e\x35"
VERSION_1_4 = b"\x67\x6f\x31\x2e\x34"
VERSION_1_3 = b"\x67\x6f\x31\x2e\x33"
VERSION_1_2 = b"\x67\x6f\x31\x2e\x32"

# Go Magic PCIntab
G012MAGIC = b"\xFB\xFF\xFF\xFF\x00\x00"
GO1XMAGIC = b"\xFF\xFF\xFF\xFB\x00\x00"


class GOPE(object):
    def __init__(self, file_path, debug=False):
        self.file_path = file_path
        self.debug = debug
        self.annoying_debug = False
        self.error = False
        self.error_message = None
        self.go_version = None
        self.pe = None
        self.bit = None
        self.size = None
        self.text = None
        self.data = None
        self.rdata = None
        self.go_base_paths = None
        self.gopclntab_section = None
        self.functab = None
        self.filetab = []
        self.itab_sym = []
        self.mod_section = None  # section that contains the
        self.module_data = None
        self.hash_sys_all = None
        self.hash_sys_main = None
        self.hash_sys_nomain = None
        self.hash_itabs = None
        self.function_main = None
        self.hash_file_paths = None
        self.stripped = None
        self.packed = False
        self.symbols = []
        self.symtab_symbols = [] # function names, symbols needed
        self.load_pe()
        if not self.error:
            self.pe_bit()
            self.is_stripped()
            self.is_packed()
            self.read_data()
            self.parse()

    def load_pe(self):
        """
        parse portable executable using Pefile.
        :return:
        """
        try:
            self.pe = pefile.PE(self.file_path)
        except Exception as e:
            self.error = True
            self.error_message = e

    def read_data(self):
        try:
            with open(self.file_path, "rb") as infile:
                self.data = infile.read()
        except Exception as e:
            self.error = True
            self.error_message = e

    def is_packed(self):
        """super simple "packer" checks for a string in the section name"""
        for section in self.pe.sections:
            for packer in [b"UPX"]:
                if packer in section.Name:
                    self.packed = True
                    if self.debug:
                        print("DEBUG: Sample is packed")
                        return

    def parse(self):
        """
        main logic for parsing the GO executable
        :return:
        """
        if self.error:
            if self.debug:
                self.error_message = "ERROR: pefile load error %s" % self.error_message
            return
        self.go_version = self.get_version_by_string()
        if not self.go_version:
            self.error_message = "ERROR: Go Version String not found"
            return
        if self.debug:
            print("DEBUG: Go Version String found %s" % self.go_version)
        # get gopclntab offset
        self.gopclntab_offset, section_va = self.find_go_pc_ln()
        if not self.gopclntab_offset:
            self.error_message = "ERROR: Go gopclntab offset not found"
            return
        # parse out symbols
        if not self.packed:
            if self.gopclntab_offset:
                self.symbols = self.parse_functab()
                self.function_main = self.get_imps("main")
                self.hash_sys_all = self.go_imp_hash()
                self.hash_sys_main = self.go_imp_hash(source="main")
                self.hash_sys_nomain = self.go_imp_hash(source="nomain")
        # use virtual address to find xref to gopclntab
        va_offset = self.pe.OPTIONAL_HEADER.ImageBase + self.gopclntab_offset + section_va
        if self.debug:
            print("DEBUG: PE Virtual Address is 0x%x" % va_offset)
        xref_pattern = self.pack_me(va_offset)
        md_offset, md_va_offset = self.find_module_data(xref_pattern)
        # parse module data table
        if not md_offset:
            if self.debug:
                print("DEBUG: Module Data Virtual offset was not found")
            self.error_message = "Module Data Virtual offset was not found"
            return
        self.parse_module_data(md_offset)
        if not self.packed:
            self.parse_file_tab()
            self.go_paths_hash()
            self.parse_itabsym()
            if self.symtab_symbols:
                self.itab_sym = self.get_itabs()
                if self.itab_sym:
                    self.hash_itabs = self.go_itabs_hash()

    def pe_bit(self):
        """
        detect bit
        :return:
        """
        if self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
            self.bit = 32
            self.size = 4
            if self.debug:
                print("DEBUG: Bit 32, size 4")
        else:
            self.bit = 64
            self.size = 8
            if self.debug:
                print("DEBUG: Bit 64, size 8")

    def ptr(self, addr, size=None):
        """
        read data at given offset, size can be modified because 64bit exes can still use 32bit sizes (4bytes)
        parses a particular section because some structures
        :param addr:
        :param size:
        :return:
        """
        if not size:
            size = self.size
        if size == 4:
            data = self.pe_section[addr:addr + size]
            return struct.unpack("<I", data)[0]
        else:
            data = self.pe_section[addr:addr + size]
            return struct.unpack("<Q", data)[0]

    def file_ptr(self, addr, size=None):
        """

        :param addr:
        :param size:
        :return:
        """
        if not size:
            size = self.size
        if size == 4:
            data = self.data[addr:addr + size]
            return struct.unpack("<I", data)[0]
        else:
            data = self.data[addr:addr + size]
            return struct.unpack("<Q", data)[0]

    def pack_me(self, ii):
        """

        :param ii:
        :return:
        """
        if self.size == 4:
            return struct.pack("<I", ii)
        else:
            return struct.pack("<Q", ii)

    def rva2file(self, offset):
        """
        convert RVA to file offset, feels hackish but accurate
        :param offset:
        :return:
        """
        for section in self.pe.sections:
            if section.VirtualAddress < (offset - self.pe.OPTIONAL_HEADER.ImageBase) < (section.VirtualAddress + section.Misc_VirtualSize):
                return abs((self.pe.OPTIONAL_HEADER.ImageBase - offset) + ( section.VirtualAddress - section.PointerToRawData))
        return

    def is_stripped(self):
        """
        checks the if the symbols contain '/'
        TODO: check if symtab section is null bytes
        -s for stripped binaries sets a singlefilepkgs to true in the go source code.
        :return:
        """
        for section in self.pe.sections:
            if b"/" in section.Name:
                self.stripped = False
                return
        self.stripped = True
        return

    def parse_functab(self):
        """

        :return:
        """
        functab = []
        base = self.gopclntab_offset
        addr = self.gopclntab_offset + 8
        size = self.ptr(addr)
        c = 0
        self.annoying_debug = False
        for item in range(1, size*2, 2):
            offset = addr + (self.size * item)
            if self.annoying_debug:
                c += 1
                print("DEBUG: Item: 0x%x, Offset: 0x%x, Size: 0x%x" % (c, offset, size))
            func_entry = self.ptr(offset)
            if self.annoying_debug:
                print("DEBUG: Function Offset 0x%x Name Offset 0x%x" % (offset, offset + self.size))
            if self.annoying_debug:
                print("DEBUG: Function RVA Offset is 0x%x" % func_entry)
            if self.annoying_debug:
                print("DEBUG: Reading offset at 0x%x" % (offset + self.size))
            entry_off = self.ptr(offset + self.size)
            if self.annoying_debug:
                print("DEBUG: Offset to function name entry 0x%x" % entry_off)
            func_addr = self.ptr(entry_off + base)
            if self.annoying_debug:
                print("DEBUG: Function Entry RVA 0x%x" % func_addr)
            func_name_offset = self.ptr(entry_off + base + self.size, size=4)
            if self.annoying_debug:
                print("DEBUG: Function Entry Offset 0x%x" % func_name_offset)
            str_offset = func_name_offset + base
            if self.annoying_debug:
                print("DEBUG: Function String Offset 0x%x" % str_offset)
            temp_name = self.pe_section[str_offset:str_offset + 256]
            # todo Use string length
            name = temp_name.split(b"\x00")[0]
            if self.annoying_debug:
                print("DEBUG: Name %s" % name)
                print()
            functab.append((func_addr, name))
        self.functab = functab
        return functab

    def check_is_gopclntab(self, addr):
        """
        TODO: Check header: 4-byte magic, two zeros, pc quantum, pointer size.
              https://github.com/golang/go/blob/52fe92fbaa41a6441144029760ada24b5be1d398/src/debug/gosym/pclntab.go
        :param addr:
        :return:
        """
        first_entry = self.ptr(addr + 8 + self.size)
        if self.debug:
            print("DEBUG: First sec offset is 0x%x" % first_entry)
        first_entry_off = self.ptr(addr + 8 + self.size * 2)
        if self.debug:
            print("DEBUG: First Entry offset is 0x%x" % first_entry_off)
        addr_func = addr + first_entry_off
        if self.debug:
            print("DEBUG: Addr Func offset is 0x%x" % addr_func)
        func_loc = self.ptr(addr_func)
        if self.debug:
            print("DEBUG: Addr Func Loc offset is 0x%x" % func_loc)
        if func_loc == first_entry:
            return True
        return False

    def find_go_pc_ln(self):
        """
        :return:
        """
        lookup = [G012MAGIC, GO1XMAGIC]
        for pattern in lookup:
            for cc, section in enumerate(self.pe.sections):
                section_data = self.pe.sections[cc].get_data()
                offset = section_data.find(pattern)
                if offset == -1:
                    continue
                else:
                    self.pe_section = self.pe.sections[cc].get_data()
                    if self.debug:
                        sec_name = section.Name.decode("utf-8").replace("\x00","")
                        print("DEBUG: gopclntab offset is 0x%x in section %s at file offset 0x%x" % (offset, sec_name, offset + section.PointerToRawData))
                    if self.check_is_gopclntab(offset):
                        return offset, section.VirtualAddress
        return None, None

    def find_module_data(self, pattern):
        """
        :param pattern:
        :return:
        """
        if self.debug:
            print("DEBUG: xref pattern %s" % binascii.hexlify(pattern))
        for cc, section in enumerate(self.pe.sections):
            section_data = self.pe.sections[cc].get_data()
            offset = section_data.find(pattern)
            if offset != -1:
                self.mod_section = section_data
                return offset, offset + section.VirtualAddress
        if self.debug:
            print("DEBUG: xref pattern %s not found" % binascii.hexlify(pattern))
        return None, None

    def parse_module_data(self, offset):
        """

        :param offset:
        :return:
        """
        # TODO add module data for older versions
        if self.go_version in ['Go 1.10', 'Go 1.11', 'Go 1.12', 'Go 1.13', 'Go 1.14', 'Go 1.15']:
            if self.bit == 32:
                self.module_data = ModuleDataGo1_10_15_32.from_buffer_copy(self.mod_section[offset:])
            else:
                self.module_data = ModuleDataGo1_10_15_64.from_buffer_copy(self.mod_section[offset:])
        # add validataion

    def parse_file_tab(self):
        # filetab virtual adddress and length is stored within the Module Data
        # .data:00000000007C19E0                 dq offset unk_1C470F0   ; filetab.array
        # .data:00000000007C19E0                 dq 25Fh                 ; filetab.len
        # .data:00000000007C19E0                 dq 25Fh                 ; filetab.cap

        # verify the filetab values have been parsec from Module Data structure
        try:
            file_tab_len = self.module_data.filetab_len
        except:
            return
        # loop through each entry in the filetab
        # skip the first entry because its the size/length
        # the offset to the string is
        # 1. read offset at filetab[index] aka
        # 2. offset + gopclntab = offset to string
        for c in range(1, file_tab_len):
            offset = self.module_data.filetab + (c*4)
            # convert filetab to offset
            file_tab_offset = self.rva2file(offset)
            index = self.file_ptr(file_tab_offset, size=4)
            file_tab_str_offset = index + self.rva2file(self.module_data.pclntable)
            temp_string = self.data[file_tab_str_offset:].split(b"\x00")[0]
            if temp_string:
                self.filetab.append(temp_string)

    def parse_itabsym(self):
        """
        itab, information runtime in table
        :return:
        """
        if self.stripped:
            return
        for section in self.pe.sections:
            if b".symtab" in section.Name:
                symbols_strings = []
                symtab = section.get_data()
                offset_string_table = self.pe.FILE_HEADER.NumberOfSymbols * 18
                string_table = symtab[offset_string_table:]
                # read 18 bytes at a time until string table
                for ci in range(0, offset_string_table, 18):
                    coff_data = symtab[ci:ci+18]
                    if not coff_data:
                        continue
                    p_data = self.parse_coff(coff_data)
                    if p_data.e_zeroes:
                        # string name is less than 8 bytes
                        api_name = coff_data[0:8].split(b"\x00")[0]
                        if api_name:
                            symbols_strings.append(api_name)
                    else:
                        # string is over 8 bytes and contains null byte
                        temp_data = string_table[p_data.e_offset:p_data.e_offset+256]
                        api_name = temp_data.split(b"\x00")[0]
                        if api_name:
                            symbols_strings.append(api_name)
                self.symtab_symbols = symbols_strings

    def parse_coff(self, data):
        """
        stucture of coff table, well kind of
        {
            char        n_name[8];  /* Symbol Name */
            long        n_value;    /* Value of Symbol */
            short       n_scnum;    /* Section Number */
            unsigned short  n_type;     /* Symbol Type */
            char        n_sclass;   /* Storage Class */
            char        n_numaux;   /* Auxiliary Count */
        }
        n_name has another check. if the first four bytes are null (00 00 00 00) then the last four byte are an offset into
        the string table. The start of the string table can be found by
            FileHeader.PointeToSybolTable + (FileHeader.NumberOfSymbols * 18).
        In ELF executables there is another section named .strtab that appears to be similar.

        source: https://wiki.osdev.org/COFF#String_Table
        """

        class COFF(ctypes.Structure):
            _pack_ = 1
            _fields_ = [
                ("e_zeroes", ctypes.c_uint), ("e_offset", ctypes.c_uint), ("e_value", ctypes.c_uint),
                ("e_scnum", ctypes.c_ushort), ("e_type", ctypes.c_ushort), ("e_sclass", ctypes.c_ubyte),
                ("e_numaux", ctypes.c_ubyte)
            ]
        cc = COFF.from_buffer_copy(data)
        return cc

    def get_version_by_string(self):
        """
        :param data:
        :return:
        """
        for cc, section in enumerate(self.pe.sections):
            data = self.pe.sections[cc].get_data()
            if VERSION_1_16 in data:
                return 'Go 1.16'
            if VERSION_1_15 in data:
                return 'Go 1.15'
            if VERSION_1_14 in data:
                return 'Go 1.14'
            if VERSION_1_13 in data:
                return 'Go 1.13'
            if VERSION_1_12 in data:
                return 'Go 1.12'
            if VERSION_1_11 in data:
                return 'Go 1.11'
            if VERSION_1_10 in data:
                return 'Go 1.10'
            if VERSION_1_9 in data:
                return 'Go 1.9'
            if VERSION_1_8 in data:
                return 'Go 1.8'
            if VERSION_1_7 in data:
                return 'Go 1.7'
            if VERSION_1_6 in data:
                return 'Go 1.6'
            if VERSION_1_5 in data:
                return 'Go 1.5'
            if VERSION_1_4 in data:
                return 'Go 1.4'
            if VERSION_1_3 in data:
                return 'Go 1.3'
            if VERSION_1_2 in data:
                return 'Go 1.2'
        return None

    def go_imp_hash(self, source="default"):
        """
        source: default, main & nomain
        :param source:
        :return:
        """
        # TODO add begins with main. not in
        if not self.functab:
            return None
        impstrs = []
        for symbol in self.functab:
            if source == "default":
                impstrs.append(symbol[1])
            elif source == "main":
                if symbol[1].startswith(b"main."):
                    impstrs.append(symbol[1])
            elif source == "nomain":
                    if not symbol[1].startswith(b"main."):
                        impstrs.append(symbol[1])
        return md5(b','.join(impstrs)).hexdigest()

    def get_itabs(self):
        """
        :return:
        """
        itabs = []
        if self.stripped:
            return None
        for symbol in self.symtab_symbols:
            if b"go.itab" in symbol:
                itabs.append(symbol)
        return itabs

    def go_itabs_hash(self):
        """
        :return:
        """
        if self.filetab:
            return md5(b','.join(self.itab_sym)).hexdigest()

    def get_imps(self, source):
        """
        :param source:
        :return:
        """
        impstrs = []
        if not self.functab:
            return None
        for symbol in self.functab:
            if source == "default":
                impstrs.append(symbol[1])
            elif source == "main":
                if symbol[1].startswith(b"main."):
                    impstrs.append(symbol[1])
            elif source == "nomain":
                    if symbol[1].find(b"main.") == -1:
                        impstrs.append(symbol[1])
        return impstrs

    def go_paths_hash(self):
        """
        :return:
        """
        base_paths = []
        if len(self.filetab) == 0 or not self.filetab:
            self.hash_file_paths = None
            return
        for path in self.filetab:
            user_path = self.filetab[-1]
            if SequenceMatcher(None, path, user_path).ratio() > .75:
                base_paths.append(path)
        base_paths.sort()
        self.go_base_paths = base_paths
        self.hash_file_paths = md5(b','.join(base_paths)).hexdigest()

    def go_filetab_hash(self):
        """
        hash file tab (source code file paths)
        :return:
        """
        if self.filetab:
            return md5(b','.join(self.filetab)).hexdigest()

    def export(self):
        """
        :return:
        """
        ee = {}
        ee["error_message"] = self.error_message
        ee["go_version"] = self.go_version
        ee["packed"] = self.packed
        ee["stripped"] = self.stripped
        ee["hash_import_all"] = self.hash_sys_all
        ee["hash_import_no_main"] = self.hash_sys_nomain
        ee["hash_import_main"] = self.hash_sys_main
        ee["hash_file_path"] = self.hash_file_paths
        ee["src_files"] = self.go_base_paths
        ee["function_main"] = self.function_main
        if not self.stripped:
            ee["hash_itabs"] = self.hash_itabs
            ee["itabs"] = self.itab_sym
        return ee

    def print_module_data10(self):
        if self.go_version in ['Go 1.10', 'Go 1.11', 'Go 1.12', 'Go 1.13', 'Go 1.14', 'Go 1.15']:
            if self.module_data:
                print("pclntable: 0x%x" % self.module_data.pclntable)  # []byte
                print("pclntable_len: 0x%x" % self.module_data.pclntable_len)
                print("pclntable_cap: 0x%x" % self.module_data.pclntable_cap)
                print("ftab: 0x%x" % self.module_data.ftab)  # []functab
                print("ftab_len: 0x%x" % self.module_data.ftab_len)
                print("ftab_cap: 0x%x" % self.module_data.ftab_cap)
                print("filetab: 0x%x" % self.module_data.filetab)  # []uint32
                print("filetab_len: 0x%x" % self.module_data.filetab_len)
                print("filetab_cap: 0x%x" % self.module_data.filetab_cap)
                print("findfunctab: 0x%x" % self.module_data.findfunctab)  # uintptr
                print("minpc: 0x%x" % self.module_data.minpc)  # uintptr
                print("maxpc: 0x%x" % self.module_data.maxpc)  # uintptr
                print("text: 0x%x" % self.module_data.text)  #
                print("etext: 0x%x" % self.module_data.etext)  # uintptr
                print("noptrdata: 0x%x" % self.module_data.noptrdata)  # uintptr
                print("enoptrdata: 0x%x" % self.module_data.enoptrdata)  # uintptr
                print("data: 0x%x" % self.module_data.data)  # uintptr
                print("edata: 0x%x" % self.module_data.edata)  # uintptr
                print("bss: 0x%x" % self.module_data.bss)  # uintptr
                print("ebss: 0x%x" % self.module_data.ebss)  # uintptr
                print("noptrbss: 0x%x" % self.module_data.noptrbss)  # uintptr
                print("enoptrbss: 0x%x" % self.module_data.enoptrbss)  # uintptr
                print("end: 0x%x" % self.module_data.end)  # uintptr
                print("gcdata: 0x%x" % self.module_data.gcdata)  # uintptr
                print("gcbss: 0x%x" % self.module_data.gcbss)  # uintptr
                print("types: 0x%x" % self.module_data.types)  # uintptr
                print("etypes: 0x%x" % self.module_data.etypes)  # uintptr
                print("textsectmap: 0x%x" % self.module_data.textsectmap)  # []textsect
                print("textsectmap_len: 0x%x" % self.module_data.textsectmap_len)
                print("textsectmap_cap: 0x%x" % self.module_data.textsectmap_cap)
                print("typelinks: 0x%x" % self.module_data.typelinks)  # []int32
                print("typelinks_len: 0x%x" % self.module_data.typelinks_len)
                print("typelinks_cap: 0x%x" % self.module_data.typelinks_cap)
                print("itablinks: 0x%x" % self.module_data.itablinks)  # []*itab
                print("itablinks_len: 0x%x" % self.module_data.itablinks_len)
                print("itablinks_cap: 0x%x" % self.module_data.itablinks_cap)
                print("ptab: 0x%x" % self.module_data.ptab)  # []ptabEntry
                print("ptab_len: 0x%x" % self.module_data.ptab_len)
                print("pluginpath: 0x%x" % self.module_data.pluginpath)  # string
                print("pkghashes: 0x%x" % self.module_data.pkghashes)  # []modulehash
                print("pkghashes_len: 0x%x" % self.module_data.pkghashes_len)
                print("pkghashes_cap: 0x%x" % self.module_data.pkghashes_cap)
                print("modulename: 0x%x" % self.module_data.modulename)  # string
                print("modulehashes: 0x%x" % self.module_data.modulehashes)  # []modulehash
                print("modulehashes_len: 0x%x" % self.module_data.modulehashes_len)
                print("modulehashes_cap: 0x%x" % self.module_data.modulehashes_cap)
                print("hasmain: 0x%x" % self.module_data.hasmain)  # uint8
                print("gcdatamask: 0x%x" % self.module_data.gcdatamask)  # bitvector
                print("gcbssmask: 0x%x" % self.module_data.gcbssmask)  # bitvector
                print("typemap: 0x%x" % self.module_data.typemap)  # map[typeOff]*_type
                print("bad: 0x%x" % self.module_data.bad)
                print("next: 0x%x" % self.module_data.next)  # next * moduledata


def decode_bytes(o):
    return o.decode('utf-8')


def save_json(ff, export):
    """

    :param ff: file path
    :param export: data
    :return:
    """
    if not ff:
        return
    try:
        with open(ff + ".json", "w") as tt_file:
            json.dump(export, tt_file, default=decode_bytes, indent=4, sort_keys=True)
    except Exception as e:
        print("ERROR: %s Exporting %s" % (e, ff))


def cluster_dir(file_path):
    export = []
    for _file in glob.glob(file_path + "/*"):
        try:
            gp = GOPE(_file)
            ee = gp.export()
            export.append((_file, ee))
        except Exception as err:
            print("CLUSTER ERROR: %s" % err)
    if export:
        cluster(export)


def export_file(file_path):
    if os.path.isdir(file_path):
        print("ERROR: Cannot export directory, please pass -x for export all")
        return
    gp = GOPE(file_path)
    ee = gp.export()
    print(ee)
    save_json(file_path, ee)


def export_dir(dir_path):
    for _file in glob.glob(dir_path + "/*"):
        gp = GOPE(_file)
        ee = gp.export()
        save_json(_file, ee)


def print_module(file_path):
    gp = GOPE(file_path)
    gp.print_module_data10()


def print_version(file_path):
    gp = GOPE(file_path)
    if gp.go_version:
        print("Go Version: %s" % gp.go_version)
    else:
        print("Error Getting Version: %s" % gp.error_message)


def triage(file_path):
    import pprint
    gp = GOPE(file_path)
    ee = gp.export()
    if ee:
        pprint.pprint(ee)


def everything(file_path):
    import pprint
    e = {}
    gp = GOPE(file_path)
    temp = vars(gp)
    for vv in temp:
        if vv != "data" or vv != "rdata" or vv != "text":
            e[vv] = temp[vv]
    pprint.pprint(e)


def save_tabs(file_path):
    e = {}
    gp = GOPE(file_path)
    if gp.functab:
        e["functab"] = gp.functab
    if gp.filetab:
        e["filetab"] = gp.filetab
    if gp.symtab_symbols:
        e["symtab"] = gp.symtab_symbols
    save_json(file_path, e)


def main():
    """
    :return:
    """
    cmd_p = argparse.ArgumentParser(description='gopep Go Portable Executable Parser')
    cmd_p.add_argument('-c', '--cluster', dest="c_dir", help="cluster directory of files")
    cmd_p.add_argument('-e', '--export', dest="e_file", help="export results of file to JSON")
    cmd_p.add_argument('-x', '--export_all', dest="ea_dir", help="export results of directory to JSONs")
    cmd_p.add_argument('-v', '--version', dest="in_file", help="print version")
    cmd_p.add_argument('-m', '--module-data', dest="md_file", help="print module data details")
    cmd_p.add_argument('-t', '--triage', dest="t_file", help="triage file, print interesting attributes")
    cmd_p.add_argument('-ev', '--everything', dest="et_file", help="print EVERYTHING!")
    cmd_p.add_argument('-st', '--savetabs', dest="save_tabs", help="Export functab, filetab & symtab to JSON")

    args = cmd_p.parse_args()
    if args.c_dir:
        # cluster
        cluster_dir(args.c_dir)
    elif args.e_file:
        # export attributes of file to JSON
        export_file(args.e_file)
    elif args.ea_dir:
        # export attributes of files in directory to JSON
        export_dir(args.ea_dir)
    elif args.in_file:
        # print version
        print_version(args.in_file)
    elif args.md_file:
        # print module data
        print_module(args.md_file)
    elif args.t_file:
        # print interesting stuff
        triage(args.t_file)
    elif args.et_file:
        # print everything in pretty format
        everything(args.et_file)
    elif args.save_tabs:
        # print everything in pretty format
        save_tabs(args.save_tabs)


if __name__ == "__main__":
    main()
