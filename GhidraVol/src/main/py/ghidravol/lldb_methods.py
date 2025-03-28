## ###
# IP: Volatility License
##
from concurrent.futures import Future, ThreadPoolExecutor
import re
import lldb

from ghidratrace import sch
from ghidratrace.client import (
    MethodRegistry, ParamDesc, Address, AddressRange, TraceObject)
from ghidralldb import util, commands
from ghidralldb.methods import REGISTRY

from . import lldb_commands


class VolatilityRoot(TraceObject):
    pass


class VolKModuleContainer(TraceObject):
    pass


class VolModuleContainer(TraceObject):
    pass


class VolProcessContainer(TraceObject):
    pass


class VolThreadContainer(TraceObject):
    pass


@REGISTRY.method(action='refresh', display="Refresh Target Processes")
def refresh_vol_processes(node: VolProcessContainer):
    """Refresh the list of processes in the target kernel."""
    with commands.open_tracked_tx('Refresh Processes'):
        util.get_debugger().HandleCommand('ghidra trace put-processes-vol')


@REGISTRY.method(action='refresh', display="Refresh Kernel Modules")
def refresh_vol_kmodules(node: VolKModuleContainer):
    """Refresh the modules list for the target kernel."""
    with commands.open_tracked_tx('Refresh Modules'):
        util.get_debugger().HandleCommand('ghidra trace put-kmodules-vol')


@REGISTRY.method(action='refresh', display="Refresh Process Threads")
def refresh_vol_threads(node: VolThreadContainer):
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        proc: lldb.SBProcess = util.get_process()
        util.get_debugger().HandleCommand(
            f'ghidra trace put-threads-vol {proc.GetProcessID()}')


@REGISTRY.method(action='refresh', display="Refresh Process Modules")
def refresh_vol_modules(node: VolModuleContainer):
    """Refresh the modules list for the process."""
    with commands.open_tracked_tx('Refresh Modules'):
        proc: lldb.SBProcess = util.get_process()
        util.get_debugger().HandleCommand(
            f'ghidra trace put-modules-vol {proc.GetProcessID()}')


@REGISTRY.method(action='refresh', display="Refresh Volatility")
def refresh_vol_all(node: VolatilityRoot):
    """Refresh the set of kernel lists."""
    with commands.open_tracked_tx('Refresh Volatility'):
        util.get_debugger().HandleCommand('ghidra trace put-all-vol')
