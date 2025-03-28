## ###
#  IP: Volatility License
##
from contextlib import contextmanager
import inspect
import os.path
import socket
import time

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, TraceObject
import psutil
from ghidravol import vol, volcmd

PAGE_SIZE = 4096


def compute_inf_state(inf):
    return 'STOPPED'


def put_processes_vol_linux(radix):
    args = ["linux.pslist.PsList"]
    keys = []
    for inf in volcmd.vol(args):
        pid = inf["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ipath = vol.PROCESS_PATTERN.format(pid=pidstr)
        keys.append(vol.PROCESS_KEY_PATTERN.format(pid=pidstr))
        infobj = commands.STATE.trace.create_object(ipath)
        istate = compute_inf_state(inf)
        infobj.set_value('State', istate)
        infobj.set_value('PID', pid)
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
    commands.STATE.trace.proxy_object_path(
        vol.PROCESSES_PATH).retain_values(keys)


def put_regions_vol_linux(pid):
    args = ["linux.proc.Maps", f"--pid={pid}"]
    keys = []
    for t in volcmd.vol(args):
        rpath = vol.REGION_PATTERN.format(pid=pid, start=r["Star"])
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
        vol.MEMORY_PATTERN.format(pid=pid)).retain_values(keys)


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
    commands.STATE.trace.proxy_object_path(
        vol.KMODULES_PATH).retain_values(keys)


def put_modules_vol_linux(pid):
    args = ["linux.elfs.Elfs", f"--pid={pid}"]
    keys = []
    for mod in volcmd.vol(args):
        name = mod["File Path"]
        mpath = vol.MODULE_PATTERN.format(pid=pid, modpath=name)
        keys.append(vol.MODULE_KEY_PATTERN.format(modpath=name))
        modobj = commands.STATE.trace.create_object(mpath)
        modobj.set_value('Start', hex(mod["Start"]))
        modobj.set_value('End', hex(mod["End"]))
        modobj.insert()
    commands.STATE.trace.proxy_object_path(
        vol.MODULES_PATTERN).retain_values(keys)


def put_threads_vol_linux(pid, radix):
    args = ["linux.pslist.PsList", "--threads",
            "--decorate-com", f"--pid={pid}"]
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
        tpath = vol.THREAD_PATTERN.format(pid=pidstr, tnum=tidstr)
        tobj = commands.STATE.trace.create_object(tpath)
        keys.append(vol.THREAD_KEY_PATTERN.format(tnum=tidstr))
        tobj = commands.STATE.trace.create_object(tpath)
        tobj.set_value('TID', tidstr)
        tobj.set_value('PID', pidstr)
        tobj.set_value('PPID', ppidstr)
        tobj.set_value('OFFSET (V)', hex(t["OFFSET (V)"]))
        tobj.set_value('COMM', t["COMM"])
        tobj.insert()
    commands.STATE.trace.proxy_object_path(
        vol.THREADS_PATTERN.format(pid=pidstr)).retain_values(keys)
