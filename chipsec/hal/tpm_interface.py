#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#


"""
Trusted Platform Module (TPM) HAL component

https://trustedcomputinggroup.org
"""

import struct
import sys
from collections import namedtuple

from chipsec.logger import logger
from chipsec.logger import print_buffer
from chipsec.hal import hal_base
from chipsec.hal import tpm

import chipsec.hal.tpm12_commands

from chipsec.hal.tpm_defines import TPM12_defines

class TPM_RESPONSE_HEADER(namedtuple('TPM_RESPONSE_HEADER', 'ResponseTag DataSize ReturnCode')):
    __slots__ = ()
    def __str__(self):
        _str = """----------------------------------------------------------------
                     TPM response header
----------------------------------------------------------------
   Response TAG: 0x{:x}
   Data Size   : 0x{:x}
   Return Code : 0x{:x}
""".format(self.ResponseTag, self.DataSize, self.ReturnCode)
        _str += "\t"
        try:
            _str += TPM12_defines.STATUS[self.ReturnCode]
        except:
            _str += "Invalid return code"
        _str += "\n"
        return _str

class TPM_BASE(hal_base.HALBase):
    def __init__(self, cs):
        super(TPM_BASE, self).__init__(cs)
        self.list_of_registers = []

    def get_registers(self):
        return self.list_of_registers

    def command(self):
        raise NotImplementedError()

    def send_command(self):
        raise NotImplementedError()

    def read_response(self):
        raise NotImplementedError()

class TPM12(TPM_BASE):
    def __init__(self, cs):
        super(TPM12, self).__init__(cs)
        self.helper = cs.helper
        self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES['TPM']['address'], 16)
        self.list_of_registers = ['TPM_ACCESS', 'TPM_STS', 'TPM_DID_VID', 'TPM_RID', 'TPM_INTF_CAPABILITY', 'TPM_INT_ENABLE']

    def command(self, commandName, locality, command_argv):
        """
        Send command to the TPM and receive data
        """
        try:
            Locality = TPM12_defines.LOCALITY[locality]
        except:
            if self.logger.HAL: self.logger.log_bad("Invalid locality value\n")
            return

        requestedUse = False

        #
        # Request locality use if needed
        #
        access_address = self.TPM_BASE | Locality | TPM12_defines.TPM_ACCESS
        if self.helper.read_mmio_reg(access_address, 4) == TPM12_defines.BEENSEIZED:
            self.helper.write_mmio_reg(access_address, 4, TPM12_defines.REQUESTUSE)
            requestedUse = True

        #
        # Build command (big endian) and send/receive
        #
        (command, size) = TPM12_defines.COMMANDS[commandName](command_argv)
        self.send_command(Locality, command, size)

        (header, data, header_blob, data_blob) = self.read_response(Locality)
        self.logger.log(header)
        print_buffer(str(data_blob))
        self.logger.log('\n')

        #
        # Release locality if needed
        #
        if requestedUse==True:
            self.helper.write_mmio_reg(access_address, 4, TPM12_defines.BEENSEIZED)
        self.helper.write_mmio_reg(access_address, 1, TPM12_defines.ACTIVELOCALITY)

    def send_command(self, Locality, command, size):
        """
        Send a command to the TPM using the locality specified
        """
        count = 0

        datafifo_address = self.TPM_BASE | Locality | TPM12_defines.TPM_DATAFIFO
        sts_address = self.TPM_BASE | Locality | TPM12_defines.TPM_STS
        access_address = self.TPM_BASE | Locality | TPM12_defines.TPM_ACCESS

        self.helper.write_mmio_reg(access_address, 1, TPM12_defines.REQUESTUSE)
        #
        # Set status to command ready
        #
        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        while (0 == (sts_value & TPM12_defines.COMMANDREADY)):
            self.helper.write_mmio_reg(sts_address, 1, TPM12_defines.COMMANDREADY)
            sts_value = self.helper.read_mmio_reg(sts_address, 1)

        while count < size:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < size):
                datafifo_value = command[count]
                if sys.version_info.major == 2:
                    datafifo_value = struct.unpack("=B", datafifo_value)[0]
                self.helper.write_mmio_reg(datafifo_address, 1, datafifo_value)
                count += 1
                burst_index += 0x1

        self.helper.write_mmio_reg(sts_address, 1, TPM12_defines.TPMGO)

    def read_response(self, Locality):
        """
        Read the TPM's response using the specified locality
        """
        count = 0
        header = ""
        header_blob = bytearray()
        data = ""
        data_blob = bytearray()
        #
        # Build FIFO address
        #
        datafifo_address = self.TPM_BASE | Locality | TPM12_defines.TPM_DATAFIFO
        access_address = self.TPM_BASE | Locality| TPM12_defines.TPM_ACCESS
        sts_address = self.TPM_BASE | Locality| TPM12_defines.TPM_STS

        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        data_avail = bin(sts_value & (1<<4))[2]
        #
        # Read data available
        #
        # watchdog?
        while data_avail == '0':
            sts_value = self.helper.read_mmio_reg(sts_address, 1)
            self.helper.write_mmio_reg(sts_address, 1, TPM12_defines.DATAAVAIL)
            data_avail = bin(sts_value & (1<<4))[2]

        while count < TPM12_defines.HEADERSIZE:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < TPM12_defines.HEADERSIZE):
                header_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                count += 1
                burst_index += 0x1

        header = TPM_RESPONSE_HEADER(*struct.unpack_from(TPM12_defines.HEADERFORMAT, header_blob))

        count = 0
        if header.DataSize > 10 and header.ReturnCode == 0:
            length = header.DataSize - TPM12_defines.HEADERSIZE
            while count < length:
                sts_value = self.helper.read_mmio_reg(sts_address, 4)
                burst_count = ((sts_value>>8) & 0xFFFFFF)
                burst_index = 0
                while (burst_index < burst_count) and (count < length):
                    data_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                    count += 1
                    burst_index += 0x1

        return (header, data, header_blob, data_blob)

# # TODO: maybe we can use an abstract TPM2.0 class for commands, and the 3 classes below will only differ in their list_of_registers (and send/read)
# class TPM20(tpm.TPM):
#     def __init__(self, cs):
#         super(TPM20_FIFO, self).__init__(cs)
#         self.helper = cs.helper
#         self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES['TPM']['address'], 16)
#         self.list_of_registers = []

#     def command(self):
#         pass

#     def send_command(self):
#         raise NotImplementedError()

#     def read_response(self):
#         raise NotImplementedError()


class TPM20_FIFO(TPM_BASE):
    def __init__(self, cs):
        super(TPM20_FIFO, self).__init__(cs)
        self.helper = cs.helper
        self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES['TPM']['address'], 16)
        self.list_of_registers = []

    def send_command(self):
        raise NotImplementedError()

    def read_response(self):
        raise NotImplementedError()


class TPM20_CRB(TPM_BASE):
    def __init__(self, cs):
        super(TPM20_CRB, self).__init__(cs)
        self.helper = cs.helper
        self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES['TPM']['address'], 16)
        self.list_of_registers = []

    def send_command(self):
        raise NotImplementedError()

    def read_response(self):
        raise NotImplementedError()


class TPM20_FIFO_LEGACY(TPM12):
    def __init__(self, cs):
        super(TPM20_FIFO_LEGACY, self).__init__(cs)
        self.helper = cs.helper
        self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES['TPM']['address'], 16)
        self.list_of_registers = ['TPM_ACCESS', 'TPM_STS', 'TPM_DID_VID', 'TPM_RID', 'TPM_INTF_CAPABILITY', 'TPM_INT_ENABLE']
