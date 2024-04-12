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

import lldb

from ghidralldb import arch, commands, hooks, methods, util
from ghidralldb.commands import convert_errors

SUBMODEL_PATH = "Volatility"
PROCESSES_PATH = SUBMODEL_PATH + '.Processes'
PROCESS_KEY_PATTERN = '[{pid}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
KMODULES_PATH = SUBMODEL_PATH + '.Modules'
KMODULE_KEY_PATTERN = '[{modpath}]'
KMODULE_PATTERN = KMODULES_PATH + KMODULE_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN

lldb.debugger.HandleCommand(
    'command script delete ghidra trace start')
lldb.debugger.HandleCommand(
    'command script add -f ghidravol.vol.ghidra_trace_start    ghidra trace start')


def compute_name():
    target = lldb.debugger.GetTargetAtIndex(0)
    progname = target.executable.basename
    if progname is None:
        return 'lldb_vol/noname'
    else:
        return 'lldb_vol/' + progname.split('/')[-1]


def start_trace(name):
    language, compiler = arch.compute_ghidra_lcsp()
    commands.STATE.trace = commands.STATE.client.create_trace(
        name, language, compiler)
    # TODO: Is adding an attribute like this recommended in Python?
    commands.STATE.trace.memory_mapper = arch.compute_memory_mapper(language)
    commands.STATE.trace.register_mapper = arch.compute_register_mapper(
        language)

    parent = os.path.dirname(inspect.getfile(inspect.currentframe()))
    schema_fn = os.path.join(parent, 'schema_vol_lldb.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with commands.STATE.trace.open_tx("Create Root Object"):
        root = commands.STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'lldb ' + util.LLDB_VERSION.full)
    util.set_convenience_variable('_ghidra_tracing', True)


@convert_errors
def ghidra_trace_start(debugger, command, result, internal_dict):
    """Start a Trace in Ghidra"""

    commands.STATE.require_client()
    name = command if len(command) > 0 else compute_name()
    commands.STATE.require_no_trace()
    start_trace(name)


def set_physical_memory(on):
    val = "1" if on else "0"
    cmd = f"process plugin packet send Qqemu.PhyMemMode:{val}"
    res = lldb.SBCommandReturnObject()
    util.get_debugger().GetCommandInterpreter().HandleCommand(cmd, res)
    if res.Succeeded() == False:
        print(f"{res.GetError()}")


def is_linux():
    osabi = util.get_convenience_variable("osabi")
    return osabi == "linux"


def is_macos():
    osabi = util.get_convenience_variable("osabi")
    return osabi == "macosx" or osabi == "ios"


def is_windows():
    osabi = util.get_convenience_variable("osabi")
    return osabi == "windows" or osabi == "Cygwin"
