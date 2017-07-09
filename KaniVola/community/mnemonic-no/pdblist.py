# ISC License
#
# Copyright (c) 2017, mnemonic AS <opensource@mnemonic.no>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""This module lists the PDB information from running services and processes.

@author:        Geir Skjotskift
@license:       ISC License
@contact:       opensource@mnemonic.no

REFERENCES:
1. Starodumov, O (2010). Matching debug information.
   Retrieved from:
     http://www.debuginfo.com/articles/debuginfomatch.html
2. MSDN Microsoft (2009). GUID Data Type
   Retrieved from:
     https://msdn.microsoft.com/en-us/library/dd354925.aspx
"""

import datetime
import ntpath
import os
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32


datatypes = {
        '_PDBGUID'      : [ 0x10, {
            'Data1'         : [ 0x00, [ 'array', 4, ['unsigned char']]],
            'Data2'         : [ 0x04, [ 'array', 2, ['unsigned char']]],
            'Data3'         : [ 0x06, [ 'array', 2, ['unsigned char']]],
            'Data4'         : [ 0x08, [ 'array', 2, ['unsigned char']]],
            'Data5'         : [ 0x0a, [ 'array', 6, ['unsigned char']]],
            }],
        '_CV_HEADER' : [ 0x8, {
            'Signature'     : [ 0x00, [ 'String', {'length': 4}]],
            'Offset'        : [ 0x04, [ 'unsigned long' ]],
            }],
        '_CV_HEADER_SIMPLE': [ 0x04, {
            'Signature'     : [ 0x00, [ 'String', {'length': 4}]]
            }],
        '_CV_INFO_PDB20' : [ None, {
            'CvHeader'      : [ 0x00, [ '_CV_HEADER' ]],
            'Signature'     : [ 0x08, [ 'unsigned long' ]],
            'Age'           : [ 0x0c, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x10, [ 'String', {'length': 0x7FFF, 'encoding': 'utf8'} ]]
            }],
        '_CV_INFO_PDB70' : [ None, {
            'CvHeader'      : [ 0x00, [ '_CV_HEADER_SIMPLE' ]],
            'Signature'     : [ 0x04, [ '_PDBGUID' ]],
            'Age'           : [ 0x14, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x18, [ 'String', {'length': 0x7FFF, 'encoding': 'utf8'} ]]
            }],
        }

codeview_signature = {
        'RSDS': "_CV_INFO_PDB70",
        'NB10': "_CV_INFO_PDB20",
        }

class _PDBGUID(obj.CType):
    def __str__(self):
        def chrarray2str(a):
            c1 = ["{0:02x}".format(x.v()) for x in a]
            return "".join(c1)
        return "{0}-{1}-{2}-{3}-{4}".format(
                chrarray2str(self.Data1),
                chrarray2str(self.Data2),
                chrarray2str(self.Data3),
                chrarray2str(self.Data4),
                chrarray2str(self.Data5))


class PDBDataTypes(obj.ProfileModification):

    def modification(self, profile):

        profile.vtypes.update(datatypes)
        profile.object_classes.update({
            '_PDBGUID': _PDBGUID
            })


class PDBList(common.AbstractWindowsCommand):
    """Extract and show the PDB information in running services and processes.

    Options:

    --renamed_only   Only show files that appears renamed (differing basename)
    """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("RENAMED_ONLY", short_option = 'r',
                help = "Output only where file appears renamed from compiled file",
                default = False,
                action = "store_true")

    def logverbose(self, msg):
        if self._config.VERBOSE:
            debug.info(msg)

    def _procs_and_modules(self, ps_list):

        for proc in ps_list:
            for mod in proc.get_load_modules():
                yield proc, mod

    def _is_valid_debug_dir(self, debug_dir, image_base, addr_space):
        if debug_dir == None:
            self.logverbose("debug_dir is None")
            return False

        if debug_dir.AddressOfRawData == 0:
            self.logverbose("debug_dir == 0")
            return False

        start_addr = image_base + debug_dir.AddressOfRawData
        if not addr_space.is_valid_address(start_addr):
            self.logverbose("Invalid address (data start): {0:#x}".format(start_addr))
            return False

        end_addr = image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1
        if not addr_space.is_valid_address(end_addr):
            self.logverbose("Invalid addres (data end): {0:#x}".format(end_addr))
            return False

        return True

    def _get_debug_symbols(self, addr_space, mod):

        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()

        if not self._is_valid_debug_dir(debug_dir, image_base, addr_space):
            self.logverbose("Invalid debugdir {0:#x} {1:#x}".format(
                debug_dir.v(),
                image_base.v()))
            return 0, None

        debug_dir_offset = image_base + debug_dir.AddressOfRawData

        cv_header = obj.Object("_CV_HEADER_SIMPLE", offset = debug_dir_offset, vm = addr_space)

        theType = codeview_signature.get(cv_header.Signature.v(), None)

        if not theType:
            self.logverbose("Unknown codeview signature: {0}".format(cv_header.Signature))
            return 0, None

        pdb_file_name_data_offset = offset_in_type(theType, "PdbFileName", addr_space)
        pdb_file_name_length = debug_dir.SizeOfData - pdb_file_name_data_offset

        codeview_data = obj.Object(theType, offset = debug_dir_offset, vm = addr_space)

        return pdb_file_name_length, codeview_data

    def _appears_renamed(self, mod, pdbinfo):

        modbasename = ntpath.basename(str(mod.FullDllName))
        modbase = os.path.splitext(modbasename)[0]
        pdbbasename = ntpath.basename(str(pdbinfo.PdbFileName))
        pdbbase = os.path.splitext(pdbbasename)[0]

        return modbase.lower() != pdbbase.lower()

    def _pdbfilename_tampered_with(self, pdbfilename, pdbfilenamesize):

        pdbfilename = unicode(pdbfilename)
        return len(bytearray(pdbfilename, "utf8"))+1 != pdbfilenamesize

    def calculate(self):

        address_space = utils.load_as(self._config)

        ps_list = win32.tasks.pslist(address_space)

        # USER modules
        for proc, mod in self._procs_and_modules(ps_list):
            proc_as = proc.get_process_address_space()
            pdbfilename_size, dbg = self._get_debug_symbols(proc_as, mod)

            if dbg is None:
                continue

            renamed = self._appears_renamed(mod, dbg)
            tampered = self._pdbfilename_tampered_with(dbg.PdbFileName, pdbfilename_size)

            if self._config.RENAMED_ONLY and not renamed and not tampered:
                continue

            yield (mod.DllBase.v(),
                   proc.UniqueProcessId,
                   proc.ImageFileName,
                   mod.FullDllName,
                   dbg.CvHeader.Signature,
                   mod.get_debug_directory().TimeDateStamp,
                   dbg.PdbFileName,
                   tampered,)


        # KERNEL modules

        for mod in win32.modules.lsmod(address_space):
            pdbfilename_size, dbg = self._get_debug_symbols(address_space, mod)

            if dbg is None:
                continue

            renamed = self._appears_renamed(mod, dbg)
            tampered = self._pdbfilename_tampered_with(dbg.PdbFileName, pdbfilename_size)

            if self._config.RENAMED_ONLY and not renamed and not tampered:
                continue

            yield (mod.DllBase.v(),
                   "-",
                   "KERNEL",
                   mod.FullDllName,
                   dbg.CvHeader.Signature,
                   mod.get_debug_directory().TimeDateStamp,
                   dbg.PdbFileName,
                   tampered)


    def render_text(self, outfd, data):

        if self._config.RENAMED_ONLY:
            outfd.write("Renamed modules only!\n")

        self.table_header(outfd, [("Offset", "#018x"),
            ("PID", ">10"),
            ("Service", "<16"),
            ("Module", "<48"),
            ("Sig", "4"),
            ("Time", "10"),
            ("Value", "")])

        for offset, pid, service, module, signature, timestamp, value, tampered in data:

            self.table_row(outfd,
                    offset, pid, service, module,
                    signature, str(datetime.date.fromtimestamp(timestamp)), value)

            if tampered:
                outfd.write("WARNING {0:#018x} PID: {1} ({2}) Size of debug directory does not match with PdbFileName string length. The value is possibly tampered with.\n".format(
                    offset, pid, module))


def offset_in_type(theType, attribute, vm):
    """Return the relative offset of an attribute within a vtype"""

    return vm.profile.vtypes[theType][1][attribute][0]
