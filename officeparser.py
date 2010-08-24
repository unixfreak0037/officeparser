#!/bin/env python

import sys
from struct import unpack
from optparse import OptionParser
from cStringIO import StringIO

DIFSECT = 0xFFFFFFFC;
FATSECT = 0xFFFFFFFD;
ENDOFCHAIN = 0xFFFFFFFE;
FREESECT = 0xFFFFFFFF;

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

class CompoundBinaryFile:
    def __init__(self, file):
        self.file = file
        self.f = open(self.file, 'rb')
        # load the header
        self.header = Header(self.f.read(512))
        self.sector_size = 2 ** self.header._uSectorShift
        self.mini_sector_size = 2 ** self.header._uMiniSectorShift

        # load the sectors marked as FAT
        self.fat_sectors = []
        for fat_sect in self.header._sectFat:
            if fat_sect != FREESECT:
                self.fat_sectors.append(fat_sect)
        
        # load any DIF sectors
        sector = self.header._sectDifStart
        while sector != ENDOFCHAIN:
            data = self.read_sector(sector)
            for value in unpack('<{0}L'.format(self.sector_size / 4), data):
                if value != FREESECT:
                    self.fat_sectors.append(value)
            # the last entry is actually a pointer to next DIF
            sector = self.fat_sectors.pop()

        # load the FAT
        self.fat = []
        for fat_sect in self.fat_sectors:
            data = self.read_sector(fat_sect)
            for value in unpack('<{0}L'.format(self.sector_size / 4), data):
                self.fat.append(value)

        # get the list of directory sectors
        self.directory = []
        buffer = self.read_stream(self.header._sectDirStart)
        for chunk in unpack("128s" * (len(buffer) / 128), buffer):
            self.directory.append(Directory(chunk))

        # load the ministream
        self.ministream = self.read_stream(self.directory[0]._sectStart)
        self.ministream = self.ministream[0:self.directory[0]._ulSize]

        # load the minifat
        self.minifat = []
        data = self.read_stream(self.header._sectMiniFatStart)
        for value in unpack('<{0}L'.format(self.sector_size / 4), data):
            self.minifat.append(value)

    def get_header(self):
        return self.header

    def read_sector(self, sector):
        self.f.seek(512 + (self.sector_size * sector))
        return self.f.read(self.sector_size)

    def read_mini_sector(self, sector):
        offset = sector * self.mini_sector_size
        return self.ministream[offset:offset + self.mini_sector_size]

    def read_fat(self, sector):
        return self.fat[sector]

    def read_mini_fat(self, sector):
        return self.minifat[sector]

    def read_mini_stream(self, sector_start):
        sector = sector_start
        buffer = StringIO()
        while sector != ENDOFCHAIN:
            buffer.write(self.read_mini_sector(sector))
            sector = self.read_mini_fat(sector)
        return buffer.getvalue()

    def read_stream(self, sector_start):
        sector = sector_start
        buffer = StringIO()
        while sector != ENDOFCHAIN:
            buffer.write(self.read_sector(sector))
            sector = self.read_fat(sector)
        return buffer.getvalue()

    def dump_fat(self):
        for sector in xrange(0, len(self.fat)):
            print '{0:08X}: {1}'.format(
                    sector, fat_value_to_str(self.fat[sector]))

    def dump_fat_sectors(self):
        for sector in self.fat_sectors:
            print '{0:08X}'.format(sector)

    def dump_mini_fat(self):
        for sector in xrange(0, len(self.minifat)):
            print '{0:08X}: {1}'.format(
                    sector, fat_value_to_str(self.minifat[sector]))
    
    def dump_directory(self):
        for x in xrange(0, len(self.directory)):
            print "Directory Index {0:08X} ({0})".format(x)
            self.directory[x].dump()
            print

    def get_stream(self, index):
        d = self.directory[index]
        if d._ulSize < self.header._ulMiniSectorCutoff:
            data = self.read_mini_stream(d._sectStart)
        else:
            data = self.read_stream(d._sectStart)
        data = data[0:d._ulSize]
        return data

class Header:
    def __init__(self, data):
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

    def dump(self):
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
    def __init__(self, data):
        self.data = data
        self.directory = unpack("<64sHbbLLL16sLQQLLHH", data)
        self._ab = self.directory[0]
        self._cb = self.directory[1]
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

    def dump(self):
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
        "{0}\n                      {1}".format(
        ''.join([x for x in self._ab[0:self._cb] if ord(x) != 0]),
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

    parser.add_option("--dump-header", dest="dump_header",
            action="store_true", default=False,
            help="dump header section")

    parser.add_option("--dump-sector", dest="dump_sector",
            type="int", default=-1,
            help="dump the given sector")

    parser.add_option("--dump-fat", dest="dump_fat",
            action="store_true", default=False,
            help="dump the FAT")

    parser.add_option("--dump-fat-sectors", dest="dump_fat_sectors",
            action="store_true", default=False,
            help="dump the sectors marked as FAT")

    parser.add_option("--dump-mini-fat", dest="dump_mini_fat",
            action="store_true", default=False,
            help="dump the miniFAT")

    parser.add_option("--dump-directory", dest="dump_directory",
            action="store_true", default=False,
            help="dump the Directory")

    parser.add_option('--dump-stream', dest='dump_stream',
            type='int', default=None,
            help="help the given stream")

    parser.add_option('--dump-ministream', dest='dump_ministream',
            action='store_true', default=False,
            help='dump the ministream to stdout')

    parser.add_option('--explode', dest='explode',
            action='store_true', default=False,
            help='store all streams as files')

    (options, args) = parser.parse_args()

    ofdoc = CompoundBinaryFile(args[0])

    if options.dump_ministream:
        sys.stdout.write(ofdoc.ministream)
        sys.exit(0)

    if options.dump_header:
        ofdoc.get_header().dump()

    if options.dump_sector > -1:
        ofdoc.dump_sector(options.dump_sector)

    if options.dump_fat:
        ofdoc.dump_fat()

    if options.dump_fat_sectors:
        ofdoc.dump_fat_sectors()

    if options.dump_mini_fat:
        ofdoc.dump_mini_fat()

    if options.dump_directory:
        ofdoc.dump_directory()

    if options.dump_stream != None:
        print ofdoc.get_stream(options.dump_stream)

    if options.explode:
        for x in xrange(1, len(ofdoc.directory)):
            f = open('exploded_{0}.dat'.format(x), 'wb')
            f.write(ofdoc.get_stream(x))
            f.close()

