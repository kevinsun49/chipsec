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

from chipsec.hal import hal_base
from chipsec.hal import acpi
from chipsec.hal import tpm_interface

TPM12 = '1.2'
TPM20 = '2.0'
TPM_CRB = 'crb'
TPM_FIFO = 'fifo'
TPM_FIFO_LEGACY = 'fifo_legacy'

TPM20_INTERFACE_ADDR = 0xFED40030

LOCALITY = {
  '0': 0x0000,
  '1': 0x1000,
  '2': 0x2000,
  '3': 0x3000,
  '4': 0x4000
}

class TPM(hal_base.HALBase):
    def __init__(self, cs):
        super(TPM, self).__init__(cs)
        self.helper = cs.helper
        self.tpm_acpi = acpi.ACPI(self.cs)
        self.version = self.read_tpm_version()
        self.interface = self.read_tpm_interface()
        self.tpm = self.init_tpm()

    def read_tpm_version(self):
        tpm12_acpi_present = self.tpm_acpi.is_ACPI_table_present('TCPA')
        tpm20_acpi_present = self.tpm_acpi.is_ACPI_table_present('TPM2')
        if (not tpm12_acpi_present and not tpm20_acpi_present):
            raise RuntimeError('No TPM recognized')  # TODO: this might need a proper error
        elif tpm12_acpi_present and not tpm20_acpi_present:
            return TPM12
        else:
            return TPM20

    def read_tpm_interface(self):
        if self.version == TPM12:
            return TPM_FIFO_LEGACY
        tpm_interface_id = self.cs.mem.read_physical_mem_dword(TPM20_INTERFACE_ADDR)
        tpm_interface_id = (int(tpm_interface_id) & 0xF)
        if tpm_interface_id == 0x0:
            return TPM_CRB
        elif tpm_interface_id == 0x1:
            return TPM_FIFO
        elif tpm_interface_id == 0xF:
            return TPM_FIFO_LEGACY
        else:
            raise RuntimeError('No TPM interface recognized')

    def init_tpm(self):
        if self.version == TPM12 and self.interface == TPM_FIFO_LEGACY:
            return tpm_interface.TPM12(self.cs)
        elif self.version == TPM20 and self.interface == TPM_CRB:
            return tpm_interface.TPM20_CRB(self.cs)
        elif self.version == TPM20 and self.interface == TPM_FIFO:
            return tpm_interface.TPM20_FIFO(self.cs)
        elif self.version == TPM20 and self.interface == TPM_FIFO_LEGACY:
            return tpm_interface.TPM20_FIFO_LEGACY(self.cs)
        else:
            raise RuntimeError('Invalid combination of TPM version and interface')

    def command(self, commandName, locality, command_argv):
        self.tpm.command(commandName, locality, command_argv)

    def send_command(self, Locality, command, size):
        self.tpm.send_command(Locality, command, size)

    def read_response(self, Locality):
        self.tpm.read_response(Locality)

    def dump_all(self, locality):
        for reg in self.tpm.get_registers():
            self.dump_register(reg, locality)

    def _log_register_header(self, register_name, locality):
        num_spaces = 32 + (-len(register_name) // 2)  # ceiling division
        self.logger.log('=' * 64)
        self.logger.log("{}{}_{}".format(' ' * num_spaces, register_name, locality))
        self.logger.log('=' * 64)

    def dump_register(self, name, locality):
        if name in self.tpm.get_registers():
            self.cs.Cfg.REGISTERS[name]['address'] = hex(int(self.cs.Cfg.REGISTERS[name]['address'], 16) ^ LOCALITY[locality])
        register = self.cs.read_register_dict(name)

        self._log_register_header(name, locality)

        max_field_len = 0
        for field in register['FIELDS']:
            if len(field) > max_field_len:
                max_field_len = len(field)
        for field in register['FIELDS']:
            self.logger.log('\t{}{}: {}'.format(field, ' ' * (max_field_len-len(field)), hex(register['FIELDS'][field]['value'])))
        else:
            return None

    def identify(self):
        print(self.tpm)
