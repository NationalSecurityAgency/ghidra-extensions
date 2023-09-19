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

import gdb

from ghidragdb import arch, commands, hooks, methods, util

SUBMODEL_PATH = "Volatility"
INFERIORS_PATH = SUBMODEL_PATH + '.Inferiors'
INFERIOR_KEY_PATTERN = '[{infnum}]'
INFERIOR_PATTERN = INFERIORS_PATH + INFERIOR_KEY_PATTERN
INF_BREAKS_PATTERN = INFERIOR_PATTERN + '.Breakpoints'
INF_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
THREADS_PATTERN = INFERIOR_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
MEMORY_PATTERN = INFERIOR_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
KMODULES_PATH = SUBMODEL_PATH + '.Modules'
KMODULE_KEY_PATTERN = '[{modpath}]'
KMODULE_PATTERN = KMODULES_PATH + KMODULE_KEY_PATTERN
MODULES_PATTERN = INFERIOR_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN

def cmd(cli_name, mi_name, cli_class, cli_repeat):

    def _cmd(func):

        class _CLICmd(gdb.Command):

            def __init__(self):
                super().__init__(cli_name, cli_class)

            def invoke(self, argument, from_tty):
                if not cli_repeat:
                    self.dont_repeat()
                argv = gdb.string_to_argv(argument)
                try:
                    func(*argv, is_mi=False, from_tty=from_tty)
                except TypeError as e:
                    # TODO: This is a bit of a hack, but it works nicely
                    raise gdb.GdbError(
                        e.args[0].replace(func.__name__ + "()", "'" + cli_name + "'"))

        _CLICmd.__doc__ = func.__doc__
        _CLICmd()

        class _MICmd(gdb.MICommand):

            def __init__(self):
                super().__init__(mi_name)

            def invoke(self, argv):
                try:
                    return func(*argv, is_mi=True)
                except TypeError as e:
                    raise gdb.GdbError(e.args[0].replace(func.__name__ + "()",
                                       mi_name))

        _MICmd.__doc__ = func.__doc__
        _MICmd()
        return func

    return _cmd


def start_trace_vol(name):
    language, compiler = arch.compute_ghidra_lcsp()
    commands.STATE.trace = commands.STATE.client.create_trace(name, language, compiler)
    # TODO: Is adding an attribute like this recommended in Python?
    commands.STATE.trace.memory_mapper = arch.compute_memory_mapper(language)
    commands.STATE.trace.register_mapper = arch.compute_register_mapper(language)

    parent = os.path.dirname(inspect.getfile(inspect.currentframe()))
    schema_fn = os.path.join(parent, 'schema_vol.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with commands.STATE.trace.open_tx("Create Root Object"):
        root = commands.STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'GNU gdb ' + util.GDB_VERSION.full)
    gdb.set_convenience_variable('_ghidra_tracing', True)


@cmd('ghidra trace vol-start', '-ghidra-trace-vol-start', gdb.COMMAND_DATA, False)
def ghidra_trace_vol_start(name=None, *, is_mi, **kwargs):
    """Start a Trace in Ghidra"""

    commands.STATE.require_client()
    if name is None:
        name = commands.compute_name()
    commands.STATE.require_no_trace()
    start_trace_vol(name)

