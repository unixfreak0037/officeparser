#!/bin/env python

import sys
from struct import unpack
from optparse import OptionParser
from cStringIO import StringIO
import logging
import re
import os
import zipfile
import tempfile

OLE_SIGNATURE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
DIFSECT = 0xFFFFFFFC;
FATSECT = 0xFFFFFFFD;
ENDOFCHAIN = 0xFFFFFFFE;
FREESECT = 0xFFFFFFFF;

MODULE_EXTENSION = "bas"
CLASS_EXTENSION = "cls"
FORM_EXTENSION = "frm"

BINFILE_PATH = "xl/vbaProject.bin"

def fat_value_to_str(value):
    if value == DIFSECT:
        return '0xFFFFFFFC (DIF)'
    elif value == FATSECT:
        return '0xFFFFFFFD (FAT)'
    elif value == ENDOFCHAIN:
        return '0xFFFFFFFE (EOC)'
    elif value == FREESECT:
        return '0xFFFFFFFF (FREE)'
    else:
        return '{0:08X} (PTR)'.format(value)

def copytoken_help(difference):
    from math import ceil, log
    bit_count = int(ceil(log(difference, 2)))
    bit_count = max([bit_count, 4])
    length_mask = 0xFFFF >> bit_count
    offset_mask = ~length_mask
    maximum_length = (0xFFFF >> bit_count) + 3
    return length_mask, offset_mask, bit_count, maximum_length

def decompress_stream(compressed_container):
    # MS-OVBA
    # 2.4.1.2
    decompressed_container = '' # result
    compressed_current = 0
    compressed_chunk_start = None
    decompressed_chunk_start = None

    sig_byte = ord(compressed_container[compressed_current])
    if sig_byte != 0x01:
        logging.error('invalid signature byte {0:02X}'.format(sig_byte))
        return None

    compressed_current += 1

    while compressed_current < len(compressed_container):
        # 2.4.1.1.5
        compressed_chunk_start = compressed_current
        compressed_chunk_header = unpack("<H", compressed_container[compressed_current:compressed_current + 2])[0]
        chunk_size = (compressed_chunk_header & 0x0FFF) + 3
        #chunk_sign = compressed_chunk_header & 0b0000000000001110
        chunk_is_compressed = (compressed_chunk_header & 0x8000) >> 15 # 1 == compressed, 0 == uncompressed

        if chunk_is_compressed != 0 and chunk_size > 4095:
            logging.warning('CompressedChunkSize > 4095 but CompressedChunkFlag == 1')
        if chunk_is_compressed == 0 and chunk_size != 4095:
            logging.warning('CompressedChunkSize != 4095 but CompressedChunkFlag == 0')
        #if chunk_sign != 0b0110:
            #logging.warning('invalid CompressedChunkSignature')

        logging.debug("chunk size = {0}".format(chunk_size))

        compressed_end = min([len(compressed_container), compressed_current + chunk_size])
        compressed_current += 2

        if chunk_is_compressed == 0: # uncompressed
            decompressed_container += compressed_container[compressed_current:compressed_current + 4096]
            compressed_current += 4096
            continue

        decompressed_chunk_start = len(decompressed_container)
        while compressed_current < compressed_end:
            flag_byte = ord(compressed_container[compressed_current])
            compressed_current += 1
            for bit_index in xrange(0, 8):
                if compressed_current >= compressed_end:
                    break
                if (1 << bit_index) & flag_byte == 0: # LiteralToken
                    decompressed_container += compressed_container[compressed_current]
                    compressed_current += 1
                    continue

                # 
                # copy tokens
                # 

                copy_token = unpack("<H", compressed_container[compressed_current:compressed_current + 2])[0]
                length_mask, offset_mask, bit_count, maximum_length = copytoken_help(len(decompressed_container) - decompressed_chunk_start)
                length = (copy_token & length_mask) + 3
                temp1 = copy_token & offset_mask
                temp2 = 16 - bit_count
                offset = (temp1 >> temp2) + 1
                copy_source = len(decompressed_container) - offset
                for index in xrange(copy_source, copy_source + length):
                    decompressed_container += decompressed_container[index]
                compressed_current += 2

    return decompressed_container

class ParserOptions:
    def __init__(
            self, 
            fail_on_invalid_sig=False):
        self.fail_on_invalid_sig = fail_on_invalid_sig

class CompoundBinaryFile:
    def __init__(self, file, parser_options=None):
        self.file = file

        # if the file is a zipfile, extract the binary part to a tempfile and continue,
        # otherwise, proceed as if a real binary file.
        if zipfile.is_zipfile(self.file):
            zfile = zipfile.ZipFile(self.file, "r")           
            data = zfile.read(BINFILE_PATH)             
            self.f = tempfile.TemporaryFile()           
            self.f.write(data)
            self.f.seek(0)                              # rewind the data file to the beginning
        else:
            self.f = open(self.file, 'rb')

        if parser_options.fail_on_invalid_sig:
            sig = self.f.read(8)
            if sig != OLE_SIGNATURE:
                logging.warning('invalid OLE signature (not an office document?)')
                sys.exit(1)
            self.f.seek(0, os.SEEK_SET)

        # load the header
        self.header = Header(self.f.read(512), parser_options)
        self.sector_size = 2 ** self.header._uSectorShift
        self.mini_sector_size = 2 ** self.header._uMiniSectorShift

        # get a sector count
        if (os.path.getsize(file) - 512) % self.sector_size != 0:
            logging.warning("last sector has invalid size")

        self.sector_count = int((os.path.getsize(file) - 512) / self.sector_size)
        logging.debug("sector count = {0}".format(self.sector_size))
        logging.debug('sector size = {0}'.format(self.sector_size))
        logging.debug('mini sector size = {0}'.format(self.mini_sector_size))

        # load the sectors marked as FAT
        self.fat_sectors = []
        for fat_sect in self.header._sectFat:
            if fat_sect != FREESECT:
                self.fat_sectors.append(fat_sect)
        
        # load any DIF sectors
        sector = self.header._sectDifStart
        buffer = [sector]
        # NOTE I've seen this have an initial value of FREESECT -- not sure why
        while sector != FREESECT and sector != ENDOFCHAIN:
            data = self.read_sector(sector)
            dif_values = [x for x in unpack('<{0}L'.format(self.sector_size / 4), data)]
            # the last entry is actually a pointer to next DIF
            next = dif_values.pop()
            for value in dif_values:
                if value != FREESECT:
                    self.fat_sectors.append(value)
            if next in buffer:
                logging.error('infinite loop detected at {0} to {1} starting at DIF'.format(sector, next))
                break
            buffer.append(next)
            sector = next

        # load the FAT
        self.fat = []
        for fat_sect in self.fat_sectors:
            data = self.read_sector(fat_sect)
            if len(data) != self.sector_size:
                logging.error('broken FAT (invalid sector size {0} != {1})'.format(len(data), self.sector_size))
            else:
                for value in unpack('<{0}L'.format(self.sector_size / 4), data):
                    self.fat.append(value)

        # get the list of directory sectors
        self.directory = []
        buffer = self.read_chain(self.header._sectDirStart)
        directory_index = 0
        for chunk in unpack("128s" * (len(buffer) / 128), buffer):
            self.directory.append(Directory(chunk, directory_index))
            directory_index += 1

        # load the ministream
        if self.directory[0]._sectStart != ENDOFCHAIN:
            self.ministream = self.read_chain(self.directory[0]._sectStart)
            #logging.debug("mini stream specified size = {0}".format(self.directory[0]._ulSize))
            if len(self.ministream) < self.directory[0]._ulSize:
                logging.warning("specified size is larger than actual stream length {0}".format(len(self.ministream)))
            self.ministream = self.ministream[0:self.directory[0]._ulSize]

            # 2.3 The locations for MiniFat sectors are stored in a standard
            # chain in the Fat, with the beginning of the chain stored in the
            # header.

            self.minifat = []
            data = StringIO(self.read_chain(self.header._sectMiniFatStart))
            while True:
                chunk = data.read(self.sector_size)
                if chunk == '':
                    break
                if len(chunk) != self.sector_size:
                    logging.warning("encountered EOF while parsing minifat")
                    continue
                for value in unpack('<{0}L'.format(self.sector_size / 4), chunk):
                    self.minifat.append(value)

    def read_sector(self, sector):
        if sector >= self.sector_count:
            logging.warning("reference to invalid sector {0:04X} ({0})".format(sector))
        self.f.seek(512 + (self.sector_size * sector))
        return self.f.read(self.sector_size)

    def read_mini_sector(self, sector):
        offset = sector * self.mini_sector_size
        return self.ministream[offset:offset + self.mini_sector_size]

    def read_fat(self, sector):
        return self.fat[sector]

    def read_mini_fat(self, sector):
        return self.minifat[sector]

    def __impl_read_chain(self, start, read_sector_f, read_fat_f):
        """Returns the entire contents of a chain starting at the given sector."""
        sector = start
        check = [ sector ] # keep a list of sectors we've already read
        buffer = StringIO()
        while sector != ENDOFCHAIN:
            buffer.write(read_sector_f(sector))
            next = read_fat_f(sector)
            if next in check:
                logging.error('infinite loop detected at {0} to {1} starting at {2}'.format(
                    sector, next, sector_start))
                return buffer.getvalue()
            check.append(next)
            sector = next
        return buffer.getvalue()

    def read_mini_chain(self, sector_start):
        return self.__impl_read_chain(sector_start, self.read_mini_sector, self.read_mini_fat)

    def read_chain(self, sector_start):
        return self.__impl_read_chain(sector_start, self.read_sector, self.read_fat)

    def print_fat_sectors(self):
        for sector in self.fat_sectors:
            print '{0:08X}'.format(sector)

    def get_stream(self, index):
        d = self.directory[index]
        if d._ulSize < self.header._ulMiniSectorCutoff:
            data = self.read_mini_chain(d._sectStart)
        else:
            data = self.read_chain(d._sectStart)
        data = data[0:d._ulSize]
        return data

    def find_stream_by_name(self, name):
        for d in self.directory:
            if d.name == name:
                return d
        return None

# TODO newer office documents can have 4096 byte headers
class Header:
    def __init__(self, data, parser_options=None):
        # sanity checks
        if len(data) < 512:
            logging.warning('document is less than 512 bytes')

        self.data = data
        self.header = unpack("<8s16sHHHHHHLLLLLLLLLL109L", data)
        self._abSig = self.header[0]
        self._clid = self.header[1]
        self._uMinorVersion = self.header[2]
        self._uDllVersion = self.header[3]
        self._uByteOrder = self.header[4]
        self._uSectorShift = self.header[5]
        self._uMiniSectorShift = self.header[6]
        self._usReserved = self.header[7]
        self._usReserved1 = self.header[8]
        self._usReserved2 = self.header[9]
        self._csectFat = self.header[10] # number of sects in FAT chain
        self._sectDirStart = self.header[11] # first sect in Directory chain
        self._signature = self.header[12]
        self._ulMiniSectorCutoff = self.header[13]
        self._sectMiniFatStart = self.header[14] # first mini-FAT sect
        self._csectMiniFat = self.header[15] # number of sects in mini-FAT
        self._sectDifStart = self.header[16] # first sect in DIF chain
        self._csectDif = self.header[17] # number of sets in DIF chain
        self._sectFat = self.header[18:] # sects of first 109 FAT sectors

    def pretty_print(self):
        print """HEADER DUMP
_abSig              = {0}
_clid               = {1}
_uMinorVersion      = {2}
_uDllVersion        = {3}
_uByteOrder         = {4}
_uSectorShift       = {5}
_uMiniSectorShift   = {6}
_usReserved         = {7}
_usReserved1        = {8}
_usReserved2        = {9}
_csectFat           = {10}
_sectDirStart       = {11}
_signature          = {12}
_ulMiniSectorCutoff = {13}
_sectMiniFatStart   = {14}
_csectMiniFat       = {15}
_sectDifStart       = {16}
_csectDif           = {17}""".format(
        ' '.join(['{0:02X}'.format(ord(x)) for x in self._abSig]),
        ' '.join(['{0:02X}'.format(ord(x)) for x in self._clid]),
        '{0:04X}'.format(self._uMinorVersion),
        '{0}'.format(self._uDllVersion),
        '{0:04X}'.format(self._uByteOrder),
        '{0} ({1} bytes)'.format(self._uSectorShift, 2 ** self._uSectorShift),
        '{0} ({1} bytes)'.format(self._uMiniSectorShift, 
                                 2 ** self._uMiniSectorShift),
        '{0:04X}'.format(self._usReserved),
        '{0:08X}'.format(self._usReserved1),
        '{0:08X}'.format(self._usReserved2),
        '{0:08X}'.format(self._csectFat),
        '{0:08X}'.format(self._sectDirStart),
        '{0:08X}'.format(self._signature),
        '{0:08X} ({1} bytes)'.format(self._ulMiniSectorCutoff, 
                                     self._ulMiniSectorCutoff),
        '{0:08X}'.format(self._sectMiniFatStart),
        '{0:08X}'.format(self._csectMiniFat),
        '{0:08X}'.format(self._sectDifStart),
        '{0:08X}'.format(self._csectDif))

        for fat in self._sectFat:
            if fat != FREESECT:
                print '_sectFat            = {0:08X}'.format(fat)

STGTY_INVALID = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_LOCKBYTES = 3
STGTY_PROPERTY = 4
STGTY_ROOT = 5

def stgty_to_str(value):
    if value == STGTY_INVALID:
        return "STGTY_INVALID"
    elif value == STGTY_STORAGE:
        return "STGTY_STORAGE"
    elif value == STGTY_STREAM:
        return "STGTY_STREAM"
    elif value == STGTY_LOCKBYTES:
        return "STGTY_LOCKBYTES"
    elif value == STGTY_PROPERTY:
        return "STGTY_PROPERTY"
    elif value == STGTY_ROOT:
        return "STGTY_ROOT"
    else:
        return "UNKNOWN VALUE {0}".format(value)

DE_RED = 0
DE_BLACK = 1

def de_to_str(value):
    if value == DE_RED:
        return "DE_RED"
    elif value == DE_BLACK:
        return "DE_BLACK"
    else:
        return "UNKNOWN VALUE {0}".format(value)

class Directory:
    def __init__(self, data, index):
        self.data = data
        self.index = index
        self.directory = unpack("<64sHbbLLL16sLQQLLHH", data)
        self._ab = self.directory[0]
        self._cb = self.directory[1]
        # convert wide chars into ASCII
        self.name = ''.join([x for x in self._ab[0:self._cb] if ord(x) != 0])
        self._mse = self.directory[2]
        self._bflags = self.directory[3]
        self._sidLeftSib = self.directory[4]
        self._sidRightSib = self.directory[5]
        self._sidChild = self.directory[6]
        self._clsId = self.directory[7]
        self._dwUserFlags = self.directory[8]
        self._time = [ self.directory[9], self.directory[10] ]
        self._sectStart = self.directory[11]
        self._ulSize = self.directory[12]
        self._dptPropType = self.directory[13]
        # last two bytes are padding

    def pretty_print(self):
        print """
_ab                 = {0}
_cb                 = {1}
_mse                = {2}
_bflags             = {3}
_sidLeftSib         = {4}
_sidRightSib        = {5}
_sidChild           = {6}
_clsId              = {7}
_dwUserFlags        = {8}
_time[0]            = {9}
_time[1]            = {10}
_sectStart          = {11}
_ulSize             = {12}
_dptPropType        = {13}""".format(
        "{0}\n                      {1}".format(self.name,
        ' '.join(['{0:02X}'.format(ord(x)) for x in self._ab[0:self._cb]])),
        #unicode(self._ab).encode('us-ascii', 'ignore'),
        '{0:04X}'.format(self._cb),
        stgty_to_str(self._mse),
        de_to_str(self._bflags),
        '{0:04X}'.format(self._sidLeftSib),
        '{0:04X}'.format(self._sidRightSib),
        '{0:04X}'.format(self._sidChild),
        ' '.join(['{0:02X}'.format(ord(x)) for x in self._clsId]),
        '{0:04X}'.format(self._dwUserFlags),
        '{0}'.format(self._time[0]),
        '{0}'.format(self._time[1]),
        '{0:08X}'.format(self._sectStart),
        '{0:08X} ({0} bytes)'.format(self._ulSize),
        '{0:04X}'.format(self._dptPropType))

if __name__ == '__main__':

    parser = OptionParser()

    parser.add_option('-l', '--log-level', dest='log_level',
            type='string', default='WARNING',
            help='Sets logging level to DEBUG, INFO, WARNING (default) or ERROR.')

    parser.add_option('-x', '--fail-on-invalid-signature', dest='fail_on_invalid_sig',
            action='store_true', default=False,
            help='Stop processing if the document is missing the required header signature.')

    parser.add_option('-H', "--print-header", dest="print_header",
            action="store_true", default=False,
            help="Print header section.")

    parser.add_option('-d', "--print-directory", dest="print_directory",
            action="store_true", default=False,
            help="Print directory structure.")

    parser.add_option('-f', "--print-fat", dest="print_fat",
            action="store_true", default=False,
            help="Print FAT structure.")

    parser.add_option('-m', "--print-mini-fat", dest="print_mini_fat",
            action="store_true", default=False,
            help="Print mini-FAT structure.")

    parser.add_option('-s', '--print-expected-file-size', dest='print_expected_file_size',
            action='store_true', default=False,
            help='Print the expected file size based on the number of FAT sectors and sector size.')

    parser.add_option('-t', "--print-streams", dest="print_streams",
            action="store_true", default=False,
            help="Print the index and names of the streams contained in the document.")

    parser.add_option('-i', "--print-invalid-fat-count", dest="print_invalid_fat_count",
            action="store_true", default=False,
            help="Prints the number of invalid FAT entries.")

    parser.add_option('--create-manifest', dest='create_manifest',
            action='store_true', default=False,
            help="Create a manifest file that contains a list of all created files.")

    parser.add_option('-o', '--output-dir', dest='output_dir',
            type='string', default='.',
            help="Directory to store all extracted files.")

    parser.add_option("--dump-sector", dest="dump_sector",
            type="int", default=None,
            help="Dump the contents of the given sector.")

    parser.add_option('--dump-stream', dest='dump_stream',
            type='int', default=None,
            help="Dump the contents of the given stream identified by directory index.")

    parser.add_option('--dump-stream-by-name', dest='dump_stream_by_name',
            type='string', default=None,
            help="Dump the contents of the given stream identified by name.")

    parser.add_option('--dump-ministream', dest='dump_ministream',
            action='store_true', default=False,
            help='Dump the entire contents of the ministream to standard output.')

    parser.add_option('--extract-streams', dest='extract_streams',
            action='store_true', default=False,
            help='Store all streams as the specified files. The string {0} in the file name is replaced with the directory index.')

    parser.add_option('--extract-ole-streams', dest='extract_ole_streams',
            action='store_true', default=False,
            help="Extract all Ole10Native streams.")

    parser.add_option('--extract-macros', dest='extract_macros',
            action='store_true', default=False,
            help='Extract all macros into .vbs files.')

    parser.add_option('--extract-unknown-sectors', dest='extract_unknown_sectors',
            action='store_true', default=False,
            help='Extract any sectors that are not represented in the FAT to unknown_sectors.dat.')

    parser.add_option('--check-stream-continuity', dest='check_stream_cont',
            action='store_true', default=False,
            help='Checks that sectors beloning to FAT chains are stored in sequential order.')

    parser.add_option('--check-fat', dest='check_fat',
            action='store_true', default=False,
            help='Checks for FAT values that point to sectors that do not exist.')

    parser.add_option('--check-orphaned-chains', dest='check_orphaned_chains',
            action='store_true', default=False,
            help='Checks for chains that are not accesible from any directory entry.')

    (options, args) = parser.parse_args()

    logging.basicConfig(level=logging.__dict__[options.log_level])

    parser_options = ParserOptions(
            fail_on_invalid_sig=options.fail_on_invalid_sig)

    ofdoc = CompoundBinaryFile(args[0], parser_options)

    if options.create_manifest:
        manifest = open(os.path.join(options.output_dir, 'manifest'), 'wb')

    # 
    # print options
    # 
    if options.print_header:
        ofdoc.header.pretty_print()

    if options.print_directory:
        for x in xrange(0, len(ofdoc.directory)):
            print "Directory Index {0:08X} ({0})".format(x)
            ofdoc.directory[x].pretty_print()
            print

    if options.print_fat:
        for sector in xrange(0, len(ofdoc.fat)):
            print '{0:08X}: {1}'.format(sector, fat_value_to_str(ofdoc.fat[sector]))

    if options.print_mini_fat:
        for sector in xrange(0, len(ofdoc.minifat)):
            print '{0:08X}: {1}'.format(sector, fat_value_to_str(ofdoc.minifat[sector]))

    if options.print_streams:
        for d in ofdoc.directory:
            if d._mse == STGTY_STREAM:
                print '{0}: {1}'.format(d.index, d.name)

    if options.print_expected_file_size:
        expected_file_size = (len([x for x in ofdoc.fat if x != FREESECT]) * ofdoc.sector_size) + 512
        actual_file_size = os.path.getsize(args[0])
        size_diff = abs(expected_file_size - actual_file_size)
        percent_diff = (float(size_diff) / float(expected_file_size)) * 100.0

        print "expected file size {0} actual {1} difference {2} ({3:0.2f}%)".format(
            expected_file_size, actual_file_size, size_diff, percent_diff)

    # 
    # analysis options
    #
    if options.check_stream_cont:
        for d in ofdoc.directory[1:]:
            if d._mse == STGTY_INVALID:
                continue
            # ignore streams in the ministream
            if d._ulSize < ofdoc.header._ulMiniSectorCutoff:
                continue

            d.pretty_print()
            if d._sectStart != ENDOFCHAIN:
                current = d._sectStart
                while True:
                    next = ofdoc.read_fat(current)
                    logging.debug("next = {0:08X}".format(next))
                    if next == ENDOFCHAIN:
                        break
                    if next - current != 1:
                        logging.warning('directory index {0} non-continuous at sector {1:08X} to {2:08X}'.format(
                            d.index, current, next))
                    current = next

    invalid_fat_sectors = 0
    if options.check_fat or options.print_invalid_fat_count:
        for value in ofdoc.fat_sectors:
            if value > ofdoc.sector_count:
                invalid_fat_sectors += 1
                if options.check_fat:
                    logging.warning('invalid FAT sector reference {0:08X}'.format(value))

    if options.print_invalid_fat_count:
        print "invalid FAT sector references: {0}".format(invalid_fat_sectors)

    invalid_fat_entries = 0
    if options.check_fat or options.print_invalid_fat_count:
        for value in xrange(0, len(ofdoc.fat)):
            ptr = ofdoc.read_fat(value)
            if ptr == DIFSECT or ptr == FATSECT or ptr == ENDOFCHAIN or ptr == FREESECT:
                continue
            if ptr > len(ofdoc.fat):
                invalid_fat_entries += 1
                if options.check_fat:
                    logging.warning('invalid FAT sector {0:08X} value {1:08X}'.format(value, ptr))

    if options.print_invalid_fat_count:
        print "invalid FAT entries: {0}".format(invalid_fat_entries)

    if options.check_orphaned_chains:
        buffer = [False for fat in ofdoc.fat]
        # directory sectors
        index = ofdoc.header._sectDirStart
        while index != ENDOFCHAIN:
            buffer[index] = True
            index = ofdoc.read_fat(index)
        # minifat sectors
        index = ofdoc.header._sectMiniFatStart
        while index != ENDOFCHAIN:
            buffer[index] = True
            index = ofdoc.read_fat(index)
        # fat sectors specified in the header
        for index in ofdoc.header._sectFat:
            if index != FREESECT:
                buffer[index] = True
        # stream sectors
        for d in ofdoc.directory:
            if d._mse == STGTY_INVALID:
                continue
            # ignore streams in the ministream
            if d.index > 0 and d._ulSize < ofdoc.header._ulMiniSectorCutoff:
                continue
            
            index = d._sectStart
            while index != ENDOFCHAIN:
                #logging.debug('checking index {0:08X}'.format(index))
                buffer[index] = True
                index = ofdoc.read_fat(index)

        for index in xrange(0, len(buffer)):
            #logging.debug('{0:08X} {1} {2}'.format(index, buffer[index], fat_value_to_str(ofdoc.read_fat(index))))
            if ofdoc.read_fat(index) == FREESECT and buffer[index] == True:
                logging.warning('FREESECT is marked as used')
            if ofdoc.read_fat(index) != FREESECT and buffer[index] == False:
                logging.warning('non-FREESECT is not used')

    #
    # dump options
    #
    if options.dump_sector:
        sys.stdout.write(ofdoc.read_sector(options.dump_sector))
        sys.exit(0)

    if options.dump_ministream:
        sys.stdout.write(ofdoc.ministream)
        sys.exit(0)

    if options.dump_stream:
        sys.stdout.write(ofdoc.get_stream(options.dump_stream))
        sys.exit(0)

    if options.dump_stream_by_name:
        d = ofdoc.find_stream_by_name(options.dump_stream_by_name)
        sys.stdout.write(ofdoc.get_stream(d.index))
        sys.exit(0)

    #
    # extraction options
    #
    if options.extract_ole_streams:
        for d in ofdoc.directory:
            if d.name == "\x01Ole10Native":
                data = ofdoc.get_stream(d.index)
                size = unpack('<L', data[0:4])[0]
                data = data[4:]
                logging.debug('size = {0:08X} ({0} bytes)'.format(size))

                # TODO 
                # haven't found the specs for this yet
                #

                unknown_short = None
                filename = []
                src_path = []
                dst_path = []
                actual_size = None
                unknown_long_1 = None
                unknown_long_2 = None

                # I thought this might be an OLE type specifier ???
                unknown_short = unpack('<H', data[0:2])[0]
                data = data[2:] 
                
                # filename
                i = 0
                while i < len(data): 
                    if ord(data[i]) == 0:
                        break
                    filename.append(data[i])
                    i += 1
                filename = ''.join(filename)
                data = data[i + 1:]

                # source path
                i = 0
                while i < len(data): 
                    if ord(data[i]) == 0:
                        break
                    src_path.append(data[i])
                    i += 1
                src_path = ''.join(src_path)
                data = data[i + 1:]

                # TODO I bet these next 8 bytes are a timestamp
                unknown_long_1 = unpack('<L', data[0:4])[0]
                data = data[4:]

                unknown_long_2 = unpack('<L', data[0:4])[0]
                data = data[4:]

                # destination path? (interesting that it has my name in there)
                i = 0
                while i < len(data): 
                    if ord(data[i]) == 0:
                        break
                    dst_path.append(data[i])
                    i += 1
                dst_path = ''.join(dst_path)
                data = data[i + 1:]

                # size of the rest of the data
                actual_size = unpack('<L', data[0:4])[0]
                data = data[4:]

                logging.debug('unknown_short = {0:04X}'.format(unknown_short))
                logging.debug('file = {0}'.format(filename))
                logging.debug('src = {0}'.format(src_path))
                logging.debug('unknown_long_1 = {0:08X}'.format(unknown_long_1))
                logging.debug('unknown_long_2 = {0:08X}'.format(unknown_long_2))
                logging.debug('dst = {0}'.format(dst_path))
                logging.debug('actual size = {0}'.format(actual_size))

                filename = os.path.join(options.output_dir, filename)
                f = open(filename, 'wb')
                f.write(data[0:actual_size])
                f.close()

                if options.create_manifest:
                    manifest.write(os.path.basename(filename))
                    manifest.write("\n")

                logging.info('created file {0}'.format(filename))

    if options.extract_streams:
        for d in ofdoc.directory:
            if d._mse == STGTY_STREAM:
                i = 0
                while True:
                    filename = os.path.join(options.output_dir, 'stream_{0}_{1}.dat'.format(d.index, i))
                    if not os.path.exists(filename):
                        break
                    i += 1
                f = open(filename, 'wb')
                f.write(ofdoc.get_stream(d.index))
                f.close()
                if options.create_manifest:
                    manifest.write(os.path.basename(filename))
                    manifest.write("\n")
                logging.debug("created file {0}".format(filename))

    while options.extract_macros:
        # this stream has to exist for macros
        project = ofdoc.find_stream_by_name('PROJECT')
        if project is None:
            logging.debug('missing PROJECT stream')
            break

        # parse PROJECT
        buffer = StringIO()
        buffer.write(ofdoc.get_stream(project.index))
        buffer.seek(0)
        re_keyval = re.compile(r'^([^=]+)=(.*)$')

        code_modules = {}
        while True:
            line = buffer.readline()
            if len(line) < 1:
                break

            line = line.strip()
            if len(line) < 1:
                continue

            # is this a section header?
            if line[0] == '[':
                header = line[1:len(line) - 1]
                continue

            m = re_keyval.match(line)
            if m == None:
                logging.warning('invalid or unknown PROJECT property line')
                logging.warning(line)
                continue

            # looking for code modules
            # add the code module as a key in the dictionary
            # the value will be the extension needed later
            if m.group(1) == 'Document':
                code_modules[m.group(2).split("\x2F")[0]] = CLASS_EXTENSION
            elif m.group(1) == 'Module':
                code_modules[m.group(2)] = MODULE_EXTENSION
            elif m.group(1) == 'Class':
                code_modules[m.group(2)] = CLASS_EXTENSION
            elif m.group(1) == 'BaseClass':
                code_modules[m.group(2)] = FORM_EXTENSION

        # this stream has to exist as well
        dir_stream = ofdoc.find_stream_by_name('dir')
        if dir_stream is None:
            logging.debug('missing dir stream')
            break

        def check_value(name, expected, value):
            if expected != value:
                logging.error("invalid value for {0} expected {1:04X} got {2:04X}".format(name, expected, value))

        dir_stream = StringIO(decompress_stream(ofdoc.get_stream(dir_stream.index)))

        # PROJECTSYSKIND Record
        PROJECTSYSKIND_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTSYSKIND_Id', 0x0001, PROJECTSYSKIND_Id)
        PROJECTSYSKIND_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTSYSKIND_Size', 0x0004, PROJECTSYSKIND_Size)
        PROJECTSYSKIND_SysKind = unpack("<L", dir_stream.read(4))[0]
        if PROJECTSYSKIND_SysKind == 0x00:
            logging.debug("16-bit Windows")
        elif PROJECTSYSKIND_SysKind == 0x01:
            logging.debug("32-bit Windows")
        elif PROJECTSYSKIND_SysKind == 0x02:
            logging.debug("Macintosh")
        elif PROJECTSYSKIND_SysKind == 0x03:
            logging.debug("64-bit Windows")
        else:
            logging.error("invalid PROJECTSYSKIND_SysKind {0:04X}".format(PROJECTSYSKIND_SysKind))

        # PROJECTLCID Record
        PROJECTLCID_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTLCID_Id', 0x0002, PROJECTLCID_Id)
        PROJECTLCID_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLCID_Size', 0x0004, PROJECTLCID_Size)
        PROJECTLCID_Lcid = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLCID_Lcid', 0x409, PROJECTLCID_Lcid)

        # PROJECTLCIDINVOKE Record
        PROJECTLCIDINVOKE_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTLCIDINVOKE_Id', 0x0014, PROJECTLCIDINVOKE_Id)
        PROJECTLCIDINVOKE_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLCIDINVOKE_Size', 0x0004, PROJECTLCIDINVOKE_Size)
        PROJECTLCIDINVOKE_LcidInvoke = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLCIDINVOKE_LcidInvoke', 0x409, PROJECTLCIDINVOKE_LcidInvoke)

        # PROJECTCODEPAGE Record
        PROJECTCODEPAGE_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTCODEPAGE_Id', 0x0003, PROJECTCODEPAGE_Id)
        PROJECTCODEPAGE_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTCODEPAGE_Size', 0x0002, PROJECTCODEPAGE_Size)
        PROJECTCODEPAGE_CodePage = unpack("<H", dir_stream.read(2))[0]

        # PROJECTNAME Record
        PROJECTNAME_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTNAME_Id', 0x0004, PROJECTNAME_Id)
        PROJECTNAME_SizeOfProjectName = unpack("<L", dir_stream.read(4))[0]
        if PROJECTNAME_SizeOfProjectName < 1 or PROJECTNAME_SizeOfProjectName > 128:
            logging.error("PROJECTNAME_SizeOfProjectName value not in range: {0}".format(PROJECTNAME_SizeOfProjectName))
        PROJECTNAME_ProjectName = dir_stream.read(PROJECTNAME_SizeOfProjectName)

        # PROJECTDOCSTRING Record
        PROJECTDOCSTRING_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTDOCSTRING_Id', 0x0005, PROJECTDOCSTRING_Id)
        PROJECTDOCSTRING_SizeOfDocString = unpack("<L", dir_stream.read(4))[0]
        if PROJECTNAME_SizeOfProjectName > 2000:
            logging.error("PROJECTDOCSTRING_SizeOfDocString value not in range: {0}".format(PROJECTDOCSTRING_SizeOfDocString))
        PROJECTDOCSTRING_DocString = dir_stream.read(PROJECTDOCSTRING_SizeOfDocString)
        PROJECTDOCSTRING_Reserved = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTDOCSTRING_Reserved', 0x0040, PROJECTDOCSTRING_Reserved)
        PROJECTDOCSTRING_SizeOfDocStringUnicode = unpack("<L", dir_stream.read(4))[0]
        if PROJECTDOCSTRING_SizeOfDocStringUnicode % 2 != 0:
            logging.error("PROJECTDOCSTRING_SizeOfDocStringUnicode is not even")
        PROJECTDOCSTRING_DocStringUnicode = dir_stream.read(PROJECTDOCSTRING_SizeOfDocStringUnicode)

        # PROJECTHELPFILEPATH Record
        PROJECTHELPFILEPATH_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTHELPFILEPATH_Id', 0x0006, PROJECTHELPFILEPATH_Id)
        PROJECTHELPFILEPATH_SizeOfHelpFile1 = unpack("<L", dir_stream.read(4))[0]
        if PROJECTHELPFILEPATH_SizeOfHelpFile1 > 260:
            logging.error("PROJECTHELPFILEPATH_SizeOfHelpFile1 value not in range: {0}".format(PROJECTHELPFILEPATH_SizeOfHelpFile1))
        PROJECTHELPFILEPATH_HelpFile1 = dir_stream.read(PROJECTHELPFILEPATH_SizeOfHelpFile1)
        PROJECTHELPFILEPATH_Reserved = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTHELPFILEPATH_Reserved', 0x0049, PROJECTHELPFILEPATH_Reserved)
        PROJECTHELPFILEPATH_SizeOfHelpFile2 = unpack("<L", dir_stream.read(4))[0]
        if PROJECTHELPFILEPATH_SizeOfHelpFile2 != PROJECTHELPFILEPATH_SizeOfHelpFile1:
            logging.error("PROJECTHELPFILEPATH_SizeOfHelpFile1 does not equal PROJECTHELPFILEPATH_SizeOfHelpFile2")
        PROJECTHELPFILEPATH_HelpFile2 = dir_stream.read(PROJECTHELPFILEPATH_SizeOfHelpFile2)
        if PROJECTHELPFILEPATH_HelpFile2 != PROJECTHELPFILEPATH_HelpFile1:
            logging.error("PROJECTHELPFILEPATH_HelpFile1 does not equal PROJECTHELPFILEPATH_HelpFile2")

        # PROJECTHELPCONTEXT Record
        PROJECTHELPCONTEXT_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTHELPCONTEXT_Id', 0x0007, PROJECTHELPCONTEXT_Id)
        PROJECTHELPCONTEXT_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTHELPCONTEXT_Size', 0x0004, PROJECTHELPCONTEXT_Size)
        PROJECTHELPCONTEXT_HelpContext = unpack("<L", dir_stream.read(4))[0]

        # PROJECTLIBFLAGS Record
        PROJECTLIBFLAGS_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTLIBFLAGS_Id', 0x0008, PROJECTLIBFLAGS_Id)
        PROJECTLIBFLAGS_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLIBFLAGS_Size', 0x0004, PROJECTLIBFLAGS_Size)
        PROJECTLIBFLAGS_ProjectLibFlags = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTLIBFLAGS_ProjectLibFlags', 0x0000, PROJECTLIBFLAGS_ProjectLibFlags)

        # PROJECTVERSION Record
        PROJECTVERSION_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTVERSION_Id', 0x0009, PROJECTVERSION_Id)
        PROJECTVERSION_Reserved = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTVERSION_Reserved', 0x0004, PROJECTVERSION_Reserved)
        PROJECTVERSION_VersionMajor = unpack("<L", dir_stream.read(4))[0]
        PROJECTVERSION_VersionMinor = unpack("<H", dir_stream.read(2))[0]

        # PROJECTCONSTANTS Record
        PROJECTCONSTANTS_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTCONSTANTS_Id', 0x000C, PROJECTCONSTANTS_Id)
        PROJECTCONSTANTS_SizeOfConstants = unpack("<L", dir_stream.read(4))[0]
        if PROJECTCONSTANTS_SizeOfConstants > 1015:
            logging.error("PROJECTCONSTANTS_SizeOfConstants value not in range: {0}".format(PROJECTCONSTANTS_SizeOfConstants))
        PROJECTCONSTANTS_Constants = dir_stream.read(PROJECTCONSTANTS_SizeOfConstants)
        PROJECTCONSTANTS_Reserved = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTCONSTANTS_Reserved', 0x003C, PROJECTCONSTANTS_Reserved)
        PROJECTCONSTANTS_SizeOfConstantsUnicode = unpack("<L", dir_stream.read(4))[0]
        if PROJECTCONSTANTS_SizeOfConstantsUnicode % 2 != 0:
            logging.error("PROJECTCONSTANTS_SizeOfConstantsUnicode is not even")
        PROJECTCONSTANTS_ConstantsUnicode = dir_stream.read(PROJECTCONSTANTS_SizeOfConstantsUnicode)

        # array of REFERENCE records
        check = None
        while True:
            check = unpack("<H", dir_stream.read(2))[0]
            logging.debug("reference type = {0:04X}".format(check))
            if check == 0x000F:
                break

            if check == 0x0016:
                # REFERENCENAME
                REFERENCE_Id = check
                REFERENCE_SizeOfName = unpack("<L", dir_stream.read(4))[0]
                REFERENCE_Name = dir_stream.read(REFERENCE_SizeOfName)
                REFERENCE_Reserved = unpack("<H", dir_stream.read(2))[0]
                check_value('REFERENCE_Reserved', 0x003E, REFERENCE_Reserved)
                REFERENCE_SizeOfNameUnicode = unpack("<L", dir_stream.read(4))[0]
                REFERENCE_NameUnicode = dir_stream.read(REFERENCE_SizeOfNameUnicode)
                continue

            if check == 0x0033:
                # REFERENCEORIGINAL (followed by REFERENCECONTROL)
                REFERENCEORIGINAL_Id = check
                REFERENCEORIGINAL_SizeOfLibidOriginal = unpack("<L", dir_stream.read(4))[0]
                REFERENCEORIGINAL_LibidOriginal = dir_stream.read(REFERENCEORIGINAL_SizeOfLibidOriginal)
                continue

            if check == 0x002F:
                # REFERENCECONTROL
                REFERENCECONTROL_Id = check
                REFERENCECONTROL_SizeTwiddled = unpack("<L", dir_stream.read(4))[0] # ignore
                REFERENCECONTROL_SizeOfLibidTwiddled = unpack("<L", dir_stream.read(4))[0]
                REFERENCECONTROL_LibidTwiddled = dir_stream.read(REFERENCECONTROL_SizeOfLibidTwiddled)
                REFERENCECONTROL_Reserved1 = unpack("<L", dir_stream.read(4))[0] # ignore
                check_value('REFERENCECONTROL_Reserved1', 0x0000, REFERENCECONTROL_Reserved1)
                REFERENCECONTROL_Reserved2 = unpack("<H", dir_stream.read(2))[0] # ignore
                check_value('REFERENCECONTROL_Reserved2', 0x0000, REFERENCECONTROL_Reserved2)
                # optional field
                check2 = unpack("<H", dir_stream.read(2))[0]
                if check2 == 0x0016:
                    REFERENCECONTROL_NameRecordExtended_Id = check
                    REFERENCECONTROL_NameRecordExtended_SizeofName = unpack("<L", dir_stream.read(4))[0]
                    REFERENCECONTROL_NameRecordExtended_Name = dir_stream.read(REFERENCECONTROL_NameRecordExtended_SizeofName)
                    REFERENCECONTROL_NameRecordExtended_Reserved = unpack("<H", dir_stream.read(2))[0]
                    check_value('REFERENCECONTROL_NameRecordExtended_Reserved', 0x003E, REFERENCECONTROL_NameRecordExtended_Reserved)
                    REFERENCECONTROL_NameRecordExtended_SizeOfNameUnicode = unpack("<L", dir_stream.read(4))[0]
                    REFERENCECONTROL_NameRecordExtended_NameUnicode = dir_stream.read(REFERENCECONTROL_NameRecordExtended_SizeOfNameUnicode)
                    REFERENCECONTROL_Reserved3 = unpack("<H", dir_stream.read(2))[0]
                else:
                    REFERENCECONTROL_Reserved3 = check2

                check_value('REFERENCECONTROL_Reserved3', 0x0030, REFERENCECONTROL_Reserved3)
                REFERENCECONTROL_SizeExtended = unpack("<L", dir_stream.read(4))[0]
                REFERENCECONTROL_SizeOfLibidExtended = unpack("<L", dir_stream.read(4))[0]
                REFERENCECONTROL_LibidExtended = dir_stream.read(REFERENCECONTROL_SizeOfLibidExtended)
                REFERENCECONTROL_Reserved4 = unpack("<L", dir_stream.read(4))[0]
                REFERENCECONTROL_Reserved5 = unpack("<H", dir_stream.read(2))[0]
                REFERENCECONTROL_OriginalTypeLib = dir_stream.read(16)
                REFERENCECONTROL_Cookie = unpack("<L", dir_stream.read(4))[0]
                continue

            if check == 0x000D:
                # REFERENCEREGISTERED
                REFERENCEREGISTERED_Id = check
                REFERENCEREGISTERED_Size = unpack("<L", dir_stream.read(4))[0]
                REFERENCEREGISTERED_SizeOfLibid = unpack("<L", dir_stream.read(4))[0]
                REFERENCEREGISTERED_Libid = dir_stream.read(REFERENCEREGISTERED_SizeOfLibid)
                REFERENCEREGISTERED_Reserved1 = unpack("<L", dir_stream.read(4))[0]
                check_value('REFERENCEREGISTERED_Reserved1', 0x0000, REFERENCEREGISTERED_Reserved1)
                REFERENCEREGISTERED_Reserved2 = unpack("<H", dir_stream.read(2))[0]
                check_value('REFERENCEREGISTERED_Reserved2', 0x0000, REFERENCEREGISTERED_Reserved2)
                continue

            if check == 0x000E:
                # REFERENCEPROJECT
                REFERENCEPROJECT_Id = check
                REFERENCEPROJECT_Size = unpack("<L", dir_stream.read(4))[0]
                REFERENCEPROJECT_SizeOfLibidAbsolute = unpack("<L", dir_stream.read(4))[0]
                REFERENCEPROJECT_LibidAbsolute = dir_stream.read(REFERENCEPROJECT_SizeOfLibidAbsolute)
                REFERENCEPROJECT_SizeOfLibidRelative = unpack("<L", dir_stream.read(4))[0]
                REFERENCEPROJECT_LibidRelative = dir_stream.read(REFERENCEPROJECT_SizeOfLibidRelative)
                REFERENCEPROJECT_MajorVersion = unpack("<L", dir_stream.read(4))[0]
                REFERENCEPROJECT_MinorVersion = unpack("<H", dir_stream.read(2))[0]
                continue

            logging.error('invalid or unknown check Id {0:04X}'.format(check))
            sys.exit(0)

        PROJECTMODULES_Id = check #unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTMODULES_Id', 0x000F, PROJECTMODULES_Id)
        PROJECTMODULES_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTMODULES_Size', 0x0002, PROJECTMODULES_Size)
        PROJECTMODULES_Count = unpack("<H", dir_stream.read(2))[0]
        PROJECTMODULES_ProjectCookieRecord_Id = unpack("<H", dir_stream.read(2))[0]
        check_value('PROJECTMODULES_ProjectCookieRecord_Id', 0x0013, PROJECTMODULES_ProjectCookieRecord_Id)
        PROJECTMODULES_ProjectCookieRecord_Size = unpack("<L", dir_stream.read(4))[0]
        check_value('PROJECTMODULES_ProjectCookieRecord_Size', 0x0002, PROJECTMODULES_ProjectCookieRecord_Size)
        PROJECTMODULES_ProjectCookieRecord_Cookie = unpack("<H", dir_stream.read(2))[0]

        logging.debug("parsing {0} modules".format(PROJECTMODULES_Count))
        for x in xrange(0, PROJECTMODULES_Count):
            MODULENAME_Id = unpack("<H", dir_stream.read(2))[0]
            check_value('MODULENAME_Id', 0x0019, MODULENAME_Id)
            MODULENAME_SizeOfModuleName = unpack("<L", dir_stream.read(4))[0]
            MODULENAME_ModuleName = dir_stream.read(MODULENAME_SizeOfModuleName)
            # account for optional sections
            section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0047:
                MODULENAMEUNICODE_Id = section_id
                MODULENAMEUNICODE_SizeOfModuleNameUnicode = unpack("<L", dir_stream.read(4))[0]
                MODULENAMEUNICODE_ModuleNameUnicode = dir_stream.read(MODULENAMEUNICODE_SizeOfModuleNameUnicode)
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001A:
                MODULESTREAMNAME_id = section_id
                MODULESTREAMNAME_SizeOfStreamName = unpack("<L", dir_stream.read(4))[0]
                MODULESTREAMNAME_StreamName = dir_stream.read(MODULESTREAMNAME_SizeOfStreamName)
                MODULESTREAMNAME_Reserved = unpack("<H", dir_stream.read(2))[0]
                check_value('MODULESTREAMNAME_Reserved', 0x0032, MODULESTREAMNAME_Reserved)
                MODULESTREAMNAME_SizeOfStreamNameUnicode = unpack("<L", dir_stream.read(4))[0]
                MODULESTREAMNAME_StreamNameUnicode = dir_stream.read(MODULESTREAMNAME_SizeOfStreamNameUnicode)
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001C:
                MODULEDOCSTRING_Id = section_id
                check_value('MODULEDOCSTRING_Id', 0x001C, MODULEDOCSTRING_Id)
                MODULEDOCSTRING_SizeOfDocString = unpack("<L", dir_stream.read(4))[0]
                MODULEDOCSTRING_DocString = dir_stream.read(MODULEDOCSTRING_SizeOfDocString)
                MODULEDOCSTRING_Reserved = unpack("<H", dir_stream.read(2))[0]
                check_value('MODULEDOCSTRING_Reserved', 0x0048, MODULEDOCSTRING_Reserved)
                MODULEDOCSTRING_SizeOfDocStringUnicode = unpack("<L", dir_stream.read(4))[0]
                MODULEDOCSTRING_DocStringUnicode = dir_stream.read(MODULEDOCSTRING_SizeOfDocStringUnicode)
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0031:
                MODULEOFFSET_Id = section_id
                check_value('MODULEOFFSET_Id', 0x0031, MODULEOFFSET_Id)
                MODULEOFFSET_Size = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULEOFFSET_Size', 0x0004, MODULEOFFSET_Size)
                MODULEOFFSET_TextOffset = unpack("<L", dir_stream.read(4))[0]
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x001E:
                MODULEHELPCONTEXT_Id = section_id
                check_value('MODULEHELPCONTEXT_Id', 0x001E, MODULEHELPCONTEXT_Id)
                MODULEHELPCONTEXT_Size = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULEHELPCONTEXT_Size', 0x0004, MODULEHELPCONTEXT_Size)
                MODULEHELPCONTEXT_HelpContext = unpack("<L", dir_stream.read(4))[0]
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x002C:
                MODULECOOKIE_Id = section_id
                check_value('MODULECOOKIE_Id', 0x002C, MODULECOOKIE_Id)
                MODULECOOKIE_Size = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULECOOKIE_Size', 0x0002, MODULECOOKIE_Size)
                MODULECOOKIE_Cookie = unpack("<H", dir_stream.read(2))[0]
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0021 or section_id == 0x0022:
                MODULETYPE_Id = section_id
                MODULETYPE_Reserved = unpack("<L", dir_stream.read(4))[0]
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0025:
                MODULEREADONLY_Id = section_id
                check_value('MODULEREADONLY_Id', 0x0025, MODULEREADONLY_Id)
                MODULEREADONLY_Reserved = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULEREADONLY_Reserved', 0x0000, MODULEREADONLY_Reserved)
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x0028:
                MODULEPRIVATE_Id = section_id
                check_value('MODULEPRIVATE_Id', 0x0028, MODULEPRIVATE_Id)
                MODULEPRIVATE_Reserved = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULEPRIVATE_Reserved', 0x0000, MODULEPRIVATE_Reserved)
                section_id = unpack("<H", dir_stream.read(2))[0]
            if section_id == 0x002B: # TERMINATOR
                MODULE_Reserved = unpack("<L", dir_stream.read(4))[0]
                check_value('MODULE_Reserved', 0x0000, MODULE_Reserved)
                section_id = None
            if section_id != None:
                logging.warning('unknown or invalid module section id {0:04X}'.format(section_id))

            logging.debug("ModuleName = {0}".format(MODULENAME_ModuleName))
            logging.debug("StreamName = {0}".format(MODULESTREAMNAME_StreamName))
            logging.debug("TextOffset = {0}".format(MODULEOFFSET_TextOffset))

            code_stream = ofdoc.find_stream_by_name(MODULESTREAMNAME_StreamName)
            code_data = ofdoc.get_stream(code_stream.index)
            logging.debug("length of code_data = {0}".format(len(code_data)))
            logging.debug("offset of code_data = {0}".format(MODULEOFFSET_TextOffset))
            code_data = code_data[MODULEOFFSET_TextOffset:]
            if len(code_data) > 0:
                code_data = decompress_stream(code_data)
                count = 0
                while True:
                    filext = code_modules[MODULENAME_ModuleName]
                    filename = os.path.join(options.output_dir, '{0}.{1}'.format(MODULENAME_ModuleName, filext))
                    count += 1
                    if not os.path.exists(filename):
                        break

                f = open(filename, 'wb')
                f.write(code_data)
                f.close()

                if options.create_manifest:
                    manifest.write(os.path.basename(filename))
                    manifest.write("\n")

                logging.debug('created file {0}'.format(filename))
            else:
                logging.warning("module stream {0} has code data length 0".format(MODULESTREAMNAME_StreamName))
        break

    if options.extract_unknown_sectors:
        i = 0
        while True:
            filename = os.path.join(options.output_dir, 'unknown_sectors_{0}.dat'.format(i))
            if not os.path.exists(filename):
                break
            i += 1
        f_in = open(args[0], 'rb')
        f_in.seek(512 + (len(ofdoc.fat) * ofdoc.sector_size))
        f_out = open(filename, 'wb')
        f_out.write(f_in.read())
        f_out.close()
        f_in.close()

        if options.create_manifest:
            manifest.write(os.path.basename(filename))
            manifest.write("\n")

        logging.debug('created file {0} size = {1}'.format(filename, os.path.getsize(filename)))
        logging.debug('header + fat allocation = {0}'.format(512 + (len(ofdoc.fat) * ofdoc.sector_size)))
        logging.debug('file size = {0}'.format(os.path.getsize(args[0])))

    if options.create_manifest:
        manifest.close()
