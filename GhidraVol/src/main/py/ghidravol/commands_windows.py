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
    threads = inf["Threads"]
    if threads <= 0:
        # TODO: Distinguish INACTIVE from TERMINATED
        return 'INACTIVE'
    return 'STOPPED'


def put_processes_vol_win(state, radix):
    args = ["windows.pslist.PsList"]
    keys = []
    for inf in volcmd.vol(args):
        pid = inf["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        ipath = vol.PROCESS_PATTERN.format(pid=pidstr)
        keys.append(vol.PROCESS_KEY_PATTERN.format(pid=pidstr))
        infobj = state.trace.create_object(ipath)
        istate = compute_inf_state(inf)
        infobj.set_value('State', istate)
        infobj.set_value('PID', pid)
        ppid = inf["PPID"]
        ppidstr = ('0x{:x}' if radix ==
                   16 else '0{:o}' if radix == 8 else '{}').format(ppid)
        infobj.set_value('PPID', ppidstr)
        infobj.set_value('ImageFileName', inf["ImageFileName"])
        infobj.set_value('Offset(V)', hex(inf["Offset(V)"]))
        infobj.set_value('# threads', inf["Threads"])
        infobj.set_value('# handles', inf["Handles"])
        infobj.set_value('Wow64', inf["Wow64"])
        infobj.set_value('CreateTime', inf["CreateTime"])
        infobj.set_value('ExitTime', inf["ExitTime"])
        infobj.insert()
    state.trace.proxy_object_path(vol.PROCESSES_PATH).retain_values(keys)


def put_regions_vol_win(state, pid):
    args = ["windows.memmap.Memmap", f"--pid={pid}"]
    keys = []
    for r in volcmd.vol(args):
        rpath = vol.REGION_PATTERN.format(pid=pid, start=r["Virtual"])
        keys.append(vol.REGION_KEY_PATTERN.format(start=r["Virtual"]))
        regobj = state.trace.create_object(rpath)
        regobj.set_value('Virtual', hex(r["Virtual"]))
        regobj.set_value('Physical', hex(r["Physical"]))
        regobj.set_value('Size', hex(r["Size"]))
        regobj.set_value('Offset in File', hex(r["Offset in File"]))
        regobj.set_value('File output', r["File output"])
        regobj.insert()
    state.trace.proxy_object_path(
        vol.MEMORY_PATTERN.format(pid=pid)).retain_values(keys)


def put_kmodules_vol_win(state):
    args = ["windows.modules.Modules"]
    ret = volcmd.vol(args)
    keys = []
    for mod in ret:
        name = mod["Name"]
        mpath = vol.KMODULE_PATTERN.format(modpath=name)
        keys.append(vol.KMODULE_KEY_PATTERN.format(modpath=name))
        modobj = state.trace.create_object(mpath)
        modobj.set_value('Base', hex(mod["Base"]))
        modobj.set_value('Offset', hex(mod["Offset"]))
        modobj.set_value('Size', hex(mod["Size"]))
        modobj.set_value('Path', mod["Path"])
        modobj.set_value('File output', mod["File output"])
        modobj.insert()
    state.trace.proxy_object_path(vol.KMODULES_PATH).retain_values(keys)


def put_modules_vol_win(state, pid):
    args = ["windows.dlllist.DllList", f"--pid={pid}"]
    keys = []
    for mod in volcmd.vol(args):
        name = mod["Name"]
        mpath = vol.MODULE_PATTERN.format(pid=pid, modpath=name)
        keys.append(vol.MODULE_KEY_PATTERN.format(modpath=name))
        modobj = state.trace.create_object(mpath)
        modobj.set_value('Base', hex(mod["Base"]))
        modobj.set_value('Size', hex(mod["Size"]))
        modobj.set_value('Path', mod["Path"])
        modobj.set_value('File output', mod["File output"])
        modobj.insert()
    state.trace.proxy_object_path(vol.MODULES_PATTERN).retain_values(keys)


def put_threads_vol_win(state, pid, radix):
    args = ["windows.tslist.TsList", f"--pid={pid}"]
    keys = []
    for t in volcmd.vol(args):
        tid = t["TID"]
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        pid = t["PID"]
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(pid)
        tpath = vol.THREAD_PATTERN.format(pid=pidstr, tnum=tidstr)
        tobj = state.trace.create_object(tpath)
        keys.append(vol.THREAD_KEY_PATTERN.format(tnum=tidstr))
        tobj = state.trace.create_object(tpath)
        tobj.set_value('TID', tid)
        tobj.set_value('PID', pidstr)
        tobj.set_value('TID', tidstr)
        tobj.set_value('_display', '[{}:{}]'.format(
            pidstr, tidstr))
        tobj.insert()
    state.trace.proxy_object_path(
        vol.THREADS_PATTERN.format(pid=pidstr)).retain_values(keys)
