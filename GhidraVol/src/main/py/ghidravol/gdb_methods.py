## ###
# IP: Volatility License
##
from concurrent.futures import Future, ThreadPoolExecutor
import re
import gdb

from ghidratrace import sch
from ghidratrace.client import (
    MethodRegistry, ParamDesc, Address, AddressRange, TraceObject)
from ghidragdb import util, commands
from ghidragdb.methods import REGISTRY

from . import gdb_commands


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
        gdb.execute('ghidra trace put-processes-vol')


@REGISTRY.method(action='refresh', display="Refresh Kernel Modules")
def refresh_vol_kmodules(node: VolKModuleContainer):
    """Refresh the modules list for the target kernl."""
    with commands.open_tracked_tx('Refresh Modules'):
        gdb.execute('ghidra trace put-kmodules-vol')


@REGISTRY.method(action='refresh', display="Refresh Process Threads")
def refresh_vol_threads(node: VolThreadContainer):
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        pid: int = gdb.selected_inferior().pid
        gdb.execute(f'ghidra trace put-threads-vol {pid}')


@REGISTRY.method(action='refresh', display="Refresh Process Modules")
def refresh_vol_modules(node: VolModuleContainer):
    """Refresh the modules list for the process."""
    with commands.open_tracked_tx('Refresh Modules'):
        pid: int = gdb.selected_inferior().pid
        gdb.execute(f'ghidra trace put-modules-vol {pid}')


@REGISTRY.method(action='refresh', display="Refresh Volatility")
def refresh_vol_all(node: VolatilityRoot):
    """Refresh the set of kernel lists."""
    with commands.open_tracked_tx('Refresh Volatility'):
        gdb.execute('ghidra trace put-all-vol')
