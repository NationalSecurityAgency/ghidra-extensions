## ###
#  IP: Volatility License
##
from concurrent.futures import Future, ThreadPoolExecutor
import re

from ghidratrace import sch
from ghidratrace.client import MethodRegistry, ParamDesc, Address, AddressRange
from ghidragdb import util, commands
from ghidragdb.methods import REGISTRY

from . import gdb_commands


@REGISTRY.method(action='refresh', display="Refresh Target Processes")
def refresh_vol_processes(node: sch.Schema('VolProcessContainer')):
    """Refresh the list of processes in the target kernel."""
    with commands.open_tracked_tx('Refresh Processes'):
        gdb.execute('ghidra trace put-processes-vol')


@REGISTRY.method(action='refresh', display="Refresh Kernel Modules")
def refresh_vol_kmodules(node: sch.Schema('VolKModuleContainer')):
    """
    Refresh the modules list for the target kernl.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        gdb.execute('ghidra trace put-kmodules-vol')


@REGISTRY.method(action='refresh', display="Refresh Process Threads")
def refresh_vol_threads(node: sch.Schema('VolThreadContainer')):
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        gdb.execute('ghidra trace put-threads-vol '+util.get_process())


@REGISTRY.method(action='refresh', display="Refresh Process Modules")
def refresh_vol_modules(node: sch.Schema('VolModuleContainer')):
    """
    Refresh the modules list for the process.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        gdb.execute('ghidra trace put-modules-vol'+util.get_process())


@REGISTRY.method(action='refresh', display="Refresh Volatility")
def refresh_vol_all(node: sch.Schema('VolatilityRoot')):
    """Refresh the set of kernel lists."""
    with commands.open_tracked_tx('Refresh Volatility'):
        gdb.execute('ghidra trace put-all-vol')
