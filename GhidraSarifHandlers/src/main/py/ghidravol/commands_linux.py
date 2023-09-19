##
# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from contextlib import contextmanager
import inspect
import os.path
import socket
import time

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, TraceObject
import psutil
from . import vol, volcmd

import gdb

from ghidragdb import arch, commands, hooks, methods, util

PAGE_SIZE = 4096

def compute_inf_state(inf):
    #for t in threads:
    #    if t.is_running():
    #        return 'RUNNING'
    return 'STOPPED'


def put_inferiors_vol_linux():
    radix = gdb.parameter('output-radix')
    args = ["linux.pslist.PsList"]
    keys = []
    for inf in volcmd.vol(args):
        pid = inf["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ipath = vol.INFERIOR_PATTERN.format(infnum=pidstr)
        keys.append(vol.INFERIOR_KEY_PATTERN.format(infnum=pidstr))
        infobj = commands.STATE.trace.create_object(ipath)
        istate = compute_inf_state(inf)
        infobj.set_value('_state', istate)
        infobj.set_value('_pid', pid)
        infobj.set_value('PID', pidstr)
        ppid = inf["PPID"]
        ppidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(ppid)
        infobj.set_value('PPID', ppidstr)
        tid = inf["TID"]
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        infobj.set_value('TID', tidstr)
        infobj.set_value('Offset (V)', hex(inf["OFFSET (V)"]))
        infobj.set_value('Comm', inf["COMM"])
        infobj.insert()
    commands.STATE.trace.proxy_object_path(vol.INFERIORS_PATH).retain_values(keys)


@vol.cmd('ghidra trace put-inferiors-vol-linux', '-ghidra-trace-put-inferiors-vol-linux',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_inferiors_vol_linux(*, is_mi, **kwargs):
    """
    Put the list of inferiors into the trace's Inferiors list.
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_inferiors_vol_linux()


def put_regions_vol_linux(infnum):
    args = ["linux.proc.Maps",f"--pid={infnum}"]
    keys = []
    for t in volcmd.vol(args):
        rpath = vol.REGION_PATTERN.format(infnum=infnum, start=r["Star"])
        keys.append(vol.REGION_KEY_PATTERN.format(start=r["Start"]))
        regobj = commands.STATE.trace.create_object(rpath)
        regobj.set_value('Start', hex(r["Start"]))
        regobj.set_value('End', hex(r["End"]))
        regobj.set_value('PgOff', hex(r["PgOff"]))
        regobj.set_value('Flags', r["Flags"])
        regobj.set_value('Process', r["Process"])
        regobj.set_value('Major', r["Major"])
        regobj.set_value('Minor', r["Minor"])
        regobj.set_value('Inode', r["Inode"])
        regobj.insert()
    commands.STATE.trace.proxy_object_path(
        vol.MEMORY_PATTERN.format(infnum=infnum)).retain_values(keys)


@vol.cmd('ghidra trace put-regions-vol-linux', '-ghidra-trace-put-regions-vol-linux', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_regions_vol_linux(infnum, *, is_mi, **kwargs):
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_regions_vol_linux(infnum)


def put_kmodules_vol_linux():
    args = ["linux.lsmod.Lsmod"]
    keys = []
    for mod in volcmd.vol(args):
        name = mod["Name"]
        mpath = vol.KMODULE_PATTERN.format(modpath=name)
        keys.append(vol.KMODULE_KEY_PATTERN.format(modpath=name))
        modobj = commands.STATE.trace.create_object(mpath)
        modobj.set_value('Offset', hex(mod["Offset"]))
        modobj.set_value('Size', hex(mod["Size"]))
        modobj.insert()
    commands.STATE.trace.proxy_object_path(vol.KMODULES_PATH).retain_values(keys)


@vol.cmd('ghidra trace put-kmodules-vol-linux', '-ghidra-trace-put-kmodules-vol-linux', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_kmodules_vol_linux(*, is_mi, **kwargs):
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_kmodules_vol_linux()


def put_modules_vol_linux(infnum):
    args = ["linux.elfs.Elfs",f"--pid={infnum}"]
    keys = []
    for mod in volcmd.vol(args):
        name = mod["File Path"]
        mpath = vol.MODULE_PATTERN.format(infnum=infnum, modpath=name)
        keys.append(vol.MODULE_KEY_PATTERN.format(modpath=name))
        modobj = commands.STATE.trace.create_object(mpath)
        modobj.set_value('Start', hex(mod["Start"]))
        modobj.set_value('End', hex(mod["End"]))
        modobj.insert()
    commands.STATE.trace.proxy_object_path(vol.MODULES_PATTERN).retain_values(keys)


@vol.cmd('ghidra trace put-modules-vol-linux', '-ghidra-trace-put-modules-vol-linux', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_modules_vol_linux(infnum, *, is_mi, **kwargs):
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_modules_vol_linux(infnum)


def put_threads_vol_linux(infnum):
    radix = gdb.parameter('output-radix')
    args = ["linux.pslist.PsList", "--threads", "--decorate-com", f"--pid={infnum}"]
    keys = []
    for t in volcmd.vol(args):
        tid = t["TID"]
        tidstr = ('0x{:x}' if radix ==
                16 else '0{:o}' if radix == 8 else '{}').format(tid)
        pid = t["PID"]
        pidstr = ('0x{:x}' if radix ==
                16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ppid = t["PPID"]
        ppidstr = ('0x{:x}' if radix ==
                16 else '0{:o}' if radix == 8 else '{}').format(ppid)
        tpath = vol.THREAD_PATTERN.format(infnum=pidstr, tnum=tidstr)
        tobj = commands.STATE.trace.create_object(tpath)
        keys.append(vol.THREAD_KEY_PATTERN.format(tnum=tidstr))
        tobj = commands.STATE.trace.create_object(tpath)
        tobj.set_value('_tid', tid)
        tobj.set_value('TID', tidstr)
        tobj.set_value('PID', pidstr)
        tobj.set_value('PPID', ppidstr)
        tobj.set_value('OFFSET (V)', hex(t["OFFSET (V)"]))
        tobj.set_value('COMM', t["COMM"])
        tobj.insert()
    commands.STATE.trace.proxy_object_path(
        vol.THREADS_PATTERN.format(infnum=pidstr)).retain_values(keys)


@vol.cmd('ghidra trace put-threads-vol-linux', '-ghidra-trace-put-threads-vol-linux', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_threads_vol_linux(infnum, *, is_mi, **kwargs):
    """
    Put the current inferior's threads into the Ghidra trace
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_threads_vol_linux(infnum)

@vol.cmd('ghidra trace put-all-vol-linux', '-ghidra-trace-put-all-vol-linux', gdb.COMMAND_DATA, True)
def ghidra_trace_put_all_vol_linux(*, is_mi, **kwargs):
    """
    Put everything currently selected into the Ghidra trace
    """

    commands.STATE.require_tx()
    with commands.STATE.client.batch() as b:
        put_inferiors_vol_linux()
        #put_kmodules_vol_linux()


