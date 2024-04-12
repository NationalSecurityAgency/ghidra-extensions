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

import gdb

from ghidragdb import arch, commands, hooks, methods, util
from ghidragdb.commands import cmd

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


def start_trace(name):
    language, compiler = arch.compute_ghidra_lcsp()
    commands.STATE.trace = commands.STATE.client.create_trace(
        name, language, compiler)
    # TODO: Is adding an attribute like this recommended in Python?
    commands.STATE.trace.memory_mapper = arch.compute_memory_mapper(language)
    commands.STATE.trace.register_mapper = arch.compute_register_mapper(
        language)

    parent = os.path.dirname(inspect.getfile(inspect.currentframe()))
    schema_fn = os.path.join(parent, 'schema_vol_gdb.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with commands.STATE.trace.open_tx("Create Root Object"):
        root = commands.STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'gdb_vol ' + util.GDB_VERSION.full)
    gdb.set_convenience_variable('_ghidra_tracing', True)


@cmd('ghidra trace start', '-ghidra-trace-start', gdb.COMMAND_DATA, False)
def ghidra_trace_start(name=None, *, is_mi, **kwargs):
    """Start a Trace in Ghidra"""

    commands.STATE.require_client()
    if name is None:
        name = commands.compute_name()
    commands.STATE.require_no_trace()
    start_trace(name)


def set_physical_memory(on):
    val = "1" if on else "0"
    cmd = f"maintenance packet Qqemu.PhyMemMode:{val}"
    gdb.execute(cmd)


def is_linux():
    osabi = arch.get_osabi()
    return osabi == "GNU/Linux"


def is_macos():
    osabi = arch.get_osabi()
    return osabi == "Darwin"


def is_windows():
    osabi = arch.get_osabi()
    return osabi == "Windows" or osabi == "Cygwin"
