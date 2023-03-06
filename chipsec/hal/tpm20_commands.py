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
Definition for TPM2.0 commands to use with TPM HAL

TCG PC Client TPM Specification
TCG TPM v2.0 Specification
"""

from typing import Dict
import struct
from chipsec.logger import logger

TPM2_STARTUP_COMMAND = 0x00000144
TPM2_SHUTDOWN_COMMAND = 0x00000145
TPM2_SELFTEST_COMMAND = 0x00000143
TPM2_NVREAD_COMMAND = 0x0000014E
TPM2_PCRREAD_COMMAND = 0x0000017E
TPM2_NVWRITE_COMMAND = 0x00000137
TPM2_NVDEFINESPACE_COMMAND = 0x0000012A
TPM2_NVUNDEFINESPACE_COMMAND = 0x00000122

TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002

SESSIONS: Dict[int, int] = {
    0: TPM_ST_NO_SESSIONS,
    1: TPM_ST_SESSIONS
}

TPM_SU: Dict[int, int] = {
    0: 0x0000,  # TPM_SU_CLEAR
    1: 0x0001   # TPM_SU_STATE
}

TPMI_YES_NO: Dict[int, int] = {
    0: 0x00,
    1: 0x01
}

TPMI_RH_NV_AUTH: Dict[int, int] = {
    1: 0x4000000C,  # TPM_RH_PLATFORM
    2: 0x40000001   # TPM_RH_OWNER
}

NV_INDEX_FIRST = 0x01 << 24
NV_INDEX_LAST = NV_INDEX_FIRST + 0x00FFFFFF

def startup(command_argv):
    """
    TPM2_Startup command.
    1: TPM_ST_CLEAR
    2: TPM_ST_STATE
    """
    session = _read_session(int(command_argv[0]), TPM_ST_NO_SESSIONS)
    command_format = '=HIIH'
    size = 0x0C000000
    try:
        startup_type = TPM_SU[int(command_argv[1])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid startup value\n")
        return

    command = struct.pack(command_format, session, size, TPM2_STARTUP_COMMAND, startup_type)
    return (command, size >> 0x18)

def shutdown(command_argv):
    """
    TPM2_Shutdown command.
    1: TPM_ST_CLEAR
    2: TPM_ST_STATE
    """
    session = _read_session(int(command_argv[0]))
    command_format = '=HIIH'
    size = 0x0C000000
    try:
        shutdown_type = TPM_SU[int(command_argv[1])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid shutdown value\n")
        return

    command = struct.pack(command_format, session, size, TPM2_SHUTDOWN_COMMAND, shutdown_type)
    return (command, size >> 0x18)

def selftest(command_argv):
    """
    TPM2_SelfTest command.
    0: YES (if full test to be performed)
    1: NO (if only test of untested functions required)
    """
    session = _read_session(int(command_argv[0]))
    command_format = '=HIIB'
    size = 0x0B000000
    try:
        selftest_yes_no = TPMI_YES_NO[int(command_argv[1])]
    except:
        if logger().HAL:
            logger().log_bad("Invalid selftest value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_SELFTEST_COMMAND, selftest_yes_no)
    return (command, size >> 0x18)

def nvread(command_argv):
    """
    TPM2_NV_Read command.
    """
    session = _read_session(int(command_argv[0]), TPM_ST_SESSIONS)
    command_format = '=HIIIIHH'
    size = 0x0
    try:
        auth = TPMI_RH_NV_AUTH[int(command_argv[1])]
        index = int(command_argv[2])
        readsize = int(command_argv[3])  # something to do with index_first and index_last...
        readoffset = int(command_argv[4])
    except:
        if logger().HAL:
            logger().log_bad("Invalid NV read value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_NVREAD_COMMAND, auth, index, readsize, readoffset)
    return (command, size >> 0x18)

def nvwrite(command_argv):
    """
    TPM2_NV_Write command.
    """
    session = _read_session(int(command_argv[0]), TPM_ST_SESSIONS)
    command_format = '=HIIIIHH'
    size = 0x0
    try:
        auth = TPMI_RH_NV_AUTH[int(command_argv[1])]
        index = int(command_argv[2])
        writesize = int(command_argv[3])
        writeoffset = int(command_argv[4])
    except:
        if logger().HAL:
            logger().log_bad("Invalid NV read value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_NVREAD_COMMAND, auth, index, writesize, writeoffset)
    return (command, size >> 0x18)

def pcrread(command_argv):
    """
    TPM2_PCR_Read command.
    """
    session = _read_session(int(command_argv[0]))
    command_format = '=HIII'
    size = 0x0C000000
    try:
        pcr_selection_in = int(command_argv[1])
    except:
        if logger().HAL:
            logger().log_bad("Invalid PCR read value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_PCRREAD_COMMAND, pcr_selection_in)
    return (command, size >> 0x18)

def nvdefinespace(command_argv):
    """
    TPM2_NV_DefineSpace command.
    """
    session = _read_session(int(command_argv[0]), TPM_ST_SESSIONS)
    command_format = '=HIIIII'
    size = 0x0
    try:
        provision = TPMI_RH_NV_AUTH[int(command_argv[1])]
        auth = int(command_argv[2])
        public_info = int(command_argv[3])
    except:
        if logger().HAL:
            logger().log_bad("Invalid NV define space value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_NVDEFINESPACE_COMMAND, provision, auth, public_info)
    return (command, size >> 0x18)

def nvundefinespace(command_argv):
    """
    TPM2_NV_UndefineSpace command.
    """
    session = _read_session(int(command_argv[0]), TPM_ST_SESSIONS)
    command_format = '=HIIII'
    size = 0x0
    try:
        provision = TPMI_RH_NV_AUTH[int(command_argv[1])]
        index = int(command_argv[2])
    except:
        if logger().HAL:
            logger().log_bad("Invalid NV define space value\n")
        return
    command = struct.pack(command_format, session, size, TPM2_NVUNDEFINESPACE_COMMAND, provision, index)


def _read_session(session_arg, required=None):
    if required and session_arg != required:
        if logger().HAL:
            logger().log_bad('Session value not allowed\n')
        return

    try:
        return SESSIONS[session_arg]
    except:
        if logger().HAL:
            logger().log_bad('Invalid session value\n')
        return
