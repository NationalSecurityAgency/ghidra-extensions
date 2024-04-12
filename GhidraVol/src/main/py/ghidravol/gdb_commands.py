## ###
#  IP: Volatility License
##
import shlex
import gdb

from ghidragdb import arch, commands, util
from ghidravol.commands_linux import *
from ghidravol.commands_macos import *
from ghidravol.commands_windows import *
from ghidravol.gdb_vol import *


@cmd('ghidra trace put-processes-vol', '-ghidra-trace-put-processes-vol',
         gdb.COMMAND_DATA, True)
def ghidra_trace_put_processes_vol(*, is_mi, **kwargs):
    """
    Put the list of processes into the trace's processes list.
    """

    set_physical_memory(True)
    radix = gdb.parameter('output-radix')
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_processes_vol_linux(commands.STATE, radix)
        if is_macos():
            put_processes_vol_macos(commands.STATE, radix)
        if is_windows():
            put_processes_vol_win(commands.STATE, radix)
    set_physical_memory(False)


@cmd('ghidra trace put-regions-vol', '-ghidra-trace-put-regions-vol', gdb.COMMAND_DATA,
         True)
def ghidra_trace_put_regions_vol(pid, *, is_mi, **kwargs):
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    set_physical_memory(True)
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_regions_vol_linux(commands.STATE, pid)
        if is_macos():
            put_regions_vol_macos(commands.STATE, pid)
        if is_windows():
            put_regions_vol_win(commands.STATE, pid)
    set_physical_memory(False)


@cmd('ghidra trace put-kmodules-vol', '-ghidra-trace-put-kmodules-vol', gdb.COMMAND_DATA,
         True)
def ghidra_trace_put_kmodules_vol(*, is_mi, **kwargs):
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    set_physical_memory(True)
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_kmodules_vol_linux(commands.STATE)
        if is_macos():
            put_kmodules_vol_macos(commands.STATE)
        if is_windows():
            put_kmodules_vol_win(commands.STATE)
    set_physical_memory(False)


@cmd('ghidra trace put-modules-vol', '-ghidra-trace-put-modules-vol', gdb.COMMAND_DATA,
         True)
def ghidra_trace_put_modules_vol(pid, *, is_mi, **kwargs):
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    set_physical_memory(True)
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_modules_vol_linux(commands.STATE, pid)
        if is_macos():
            put_modules_vol_macos(commands.STATE, pid)
        if is_windows():
            put_modules_vol_win(commands.STATE, pid)
    set_physical_memory(False)


@cmd('ghidra trace put-threads-vol', '-ghidra-trace-put-threads-vol', gdb.COMMAND_DATA,
         True)
def ghidra_trace_put_threads_vol(pid, *, is_mi, **kwargs):
    """
    Put the current process's threads into the Ghidra trace
    """

    set_physical_memory(True)
    radix = gdb.parameter('output-radix')
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_threads_vol_linux(commands.STATE, pid, radix)
        if is_macos():
            put_threads_vol_macos(commands.STATE, pid, radix)
        if is_windows():
            put_threads_vol_win(commands.STATE, pid, radix)
    set_physical_memory(False)


@cmd('ghidra trace put-all-vol', '-ghidra-trace-put-all-vol', gdb.COMMAND_DATA, True)
def ghidra_trace_put_all_vol(*, is_mi, **kwargs):
    """
    Put everything currently selected into the Ghidra trace
    """

    set_physical_memory(True)
    radix = gdb.parameter('output-radix')
    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        if is_linux():
            put_processes_vol_linux(commands.STATE, radix)
            put_kmodules_vol_linux(commands.STATE)
        if is_macos():
            put_processes_vol_macos(commands.STATE, radix)
            put_kmodules_vol_macos(commands.STATE)
        if is_windows():
            put_processes_vol_win(commands.STATE, radix)
            put_kmodules_vol_win(commands.STATE)
    set_physical_memory(False)
