## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
import re
import sys
from typing import Annotated, Optional, Union

from ghidratrace import sch
from ghidratrace.client import (
    MethodRegistry, ParamDesc, Address, AddressRange, TraceObject)

import frida # type: ignore

from . import util, commands


REGISTRY = MethodRegistry(ThreadPoolExecutor(
    max_workers=1, thread_name_prefix='MethodRegistry'))


def extre(base, ext):
    return re.compile(base.pattern + ext)


WATCHPOINT_PATTERN = re.compile('Watchpoints\\[(?P<watchnum>\\d*)\\]')
BREAKPOINT_PATTERN = re.compile('Breakpoints\\[(?P<breaknum>\\d*)\\]')
BREAK_LOC_PATTERN = extre(BREAKPOINT_PATTERN, '\\[(?P<locnum>\\d*)\\]')
SESSIONS_PATTERN = re.compile('Sessions')
SESSION_PATTERN = extre(SESSIONS_PATTERN, '\\[(?P<sid>\\w*)\\]')
AVAILABLE_PATTERN = extre(SESSION_PATTERN, '\\.Available\\[(?P<pid>\\d*)\\]')
PROCESSES_PATTERN = extre(SESSION_PATTERN, '\\.Processes')
PROCESS_PATTERN = extre(PROCESSES_PATTERN, '\\[(?P<pid>\\d*)\\]')
PROC_BREAKS_PATTERN = extre(PROCESS_PATTERN, '\\.Debug.Breakpoints')
PROC_BREAKBPT_PATTERN = extre(PROC_BREAKS_PATTERN, '\\[(?P<breaknum>\\d*)\\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\\[(?P<tid>\\w*)\\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\\[(?P<level>\\d*)\\]')
REGS_PATTERN0 = extre(THREAD_PATTERN, '.Registers')
REGS_PATTERN = extre(FRAME_PATTERN, '.Registers')
MEMORY_PATTERN = extre(PROCESS_PATTERN, '\\.Memory')
REGION_PATTERN = extre(MEMORY_PATTERN, '\\[(?P<addr>\\w*)\\]')
MODULES_PATTERN = extre(PROCESS_PATTERN, '\\.Modules')
MODULE_PATTERN = extre(
    MODULES_PATTERN, '\\[(?P<modpath>[a-zA-Z0-9_\\-\\.\\/]*)\\]')
SECTIONS_PATTERN = extre(MODULE_PATTERN, '\\.Sections')
SECTION_PATTERN = extre(SECTIONS_PATTERN, '\\[(?P<addr>\\w*)\\]')
DEPENDENCIES_PATTERN = extre(MODULE_PATTERN, '\\.Dependencies')
EXPORTS_PATTERN = extre(MODULE_PATTERN, '\\.Exports')
EXPORT_PATTERN = extre(EXPORTS_PATTERN, '\\[(?P<addr>\\w*)\\]')
IMPORTS_PATTERN = extre(MODULE_PATTERN, '\\.Imports')
IMPORT_PATTERN = extre(IMPORTS_PATTERN, '\\[(?P<addr>\\w*)\\]')
SYMBOLS_PATTERN = extre(MODULE_PATTERN, '\\.Symbols')
SYMBOL_PATTERN = extre(SYMBOLS_PATTERN, '\\[(?P<addr>\\w*)\\]')


def find_object_by_pattern(pattern, object, key, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    return mat[key]


def find_availpid_by_obj(object):
    return int(find_object_by_pattern(AVAILABLE_PATTERN, object, 'pid', "an Available"))


def find_session_by_obj(object):
    return int(find_object_by_pattern(SESSION_PATTERN, object, 'sid', "a Session"))


def find_proc_by_obj(object):
    return int(find_object_by_pattern(PROCESS_PATTERN, object, 'pid', "an Process"))


def find_proc_by_procbreak_obj(object):
    return find_object_by_pattern(PROC_BREAKS_PATTERN, object, 'pid',
                                  "a BreakpointLocationContainer")
    

def find_proc_by_env_obj(object):
    return find_object_by_pattern(ENV_PATTERN, object, 'pid', "an Environment")


def find_proc_by_threads_obj(object):
    return find_object_by_pattern(THREADS_PATTERN, object, 'pid', "a ThreadContainer")


def find_proc_by_mem_obj(object):
    return find_object_by_pattern(MEMORY_PATTERN, object, 'pid', "a Memory")


def find_proc_by_modules_obj(object):
    return find_object_by_pattern(MODULES_PATTERN, object, 'pid', "a ModuleContainer")


def find_region_by_obj(object):
    return find_object_by_pattern(REGION_PATTERN, object, 'addr', "a Region")


def find_module_by_obj(object):
    return find_object_by_pattern(MODULE_PATTERN, object, 'modpath', "a Module")


def find_section_by_obj(object):
    return find_object_by_pattern(SECTION_PATTERN, object, 'addr', "a Section")


def find_module_by_dependencies_obj(object):
    return find_object_by_pattern(DEPENDENCIES_PATTERN, object, 'modpath', "a DependencyContainer")


def find_module_by_exports_obj(object):
    return find_object_by_pattern(EXPORTS_PATTERN, object, 'modpath', "a ExportContainer")


def find_module_by_imports_obj(object):
    return find_object_by_pattern(IMPORTS_PATTERN, object, 'modpath', "a ImportContainer")


def find_module_by_sections_obj(object):
    return find_object_by_pattern(SECTIONS_PATTERN, object, 'modpath', "a SectionContainer")


def find_module_by_symbols_obj(object):
    return find_object_by_pattern(SYMBOLS_PATTERN, object, 'modpath', "a SymbolContainer")


def find_thread_by_obj(object):
    return find_object_by_pattern(THREAD_PATTERN, object, 'tid', "a Thread")


def find_thread_by_stack_obj(object):
    return find_object_by_pattern(STACK_PATTERN, object, 'tid', "a Stack")


def find_thread_by_regs_obj(object):
    return find_object_by_pattern(REGS_PATTERN0, object, 'tid', "a RegisterValueContainer")


def find_frame_by_obj(object):
    return int(find_object_by_pattern(FRAME_PATTERN, object, 'level', "a StackFrame"))


def find_export_by_obj(object):
    return find_object_by_pattern(EXPORT_PATTERN, object, 'addr', "an Import")


def find_import_by_obj(object):
    return find_object_by_pattern(IMPORT_PATTERN, object, 'addr', "an Import")


def find_symbol_by_obj(object):
    return find_object_by_pattern(SYMBOL_PATTERN, object, 'addr', "an Import")


shared_globals = dict()


class Attachable(TraceObject):
    pass


class AvailableContainer(TraceObject):
    pass


class BreakpointContainer(TraceObject):
    pass


class BreakpointLocationContainer(TraceObject):
    pass


class DependencyContainer(TraceObject):
    pass


class Environment(TraceObject):
    pass


class Export(TraceObject):
    pass


class ExportContainer(TraceObject):
    pass


class Import(TraceObject):
    pass


class ImportContainer(TraceObject):
    pass


class KernelMemory(TraceObject):
    pass


class KernelModuleContainer(TraceObject):
    pass


class Memory(TraceObject):
    pass


class MemoryRegion(TraceObject):
    pass


class Module(TraceObject):
    pass


class ModuleContainer(TraceObject):
    pass


class Process(TraceObject):
    pass


class ProcessContainer(TraceObject):
    pass


class RegisterValueContainer(TraceObject):
    pass


class Section(TraceObject):
    pass


class SectionContainer(TraceObject):
    pass


class Session(TraceObject):
    pass


class SessionContainer(TraceObject):
    pass


class Stack(TraceObject):
    pass


class StackFrame(TraceObject):
    pass


class Symbol(TraceObject):
    pass


class SymbolContainer(TraceObject):
    pass


class Thread(TraceObject):
    pass


class ThreadContainer(TraceObject):
    pass


@REGISTRY.method(display='connect to device')
def connect_device(session: Session) -> None:
    """Execute a Python3 command or script."""
    # TODO: UNTESTED
    id = find_session_by_obj(session)
    with commands.open_tracked_tx('Connect Device'):
        commands.attach_by_device(id)


@REGISTRY.method()
def execute(cmd: str, to_string: bool = False,
            callback: str = "on_message_print") -> Optional[str]:
    """Execute a Python3 command or script."""
    name = "exec"
    if to_string:
        data = StringIO()
        with redirect_stdout(data):
            util.run_script(name, cmd, find_callback(callback))
        return data.getvalue()
    else:
        util.run_script(name, cmd, find_callback(callback))
        return None


@REGISTRY.method(action='refresh', display='refresh')
def refresh_available(node: AvailableContainer) -> None:
    """List processes on pydbg's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        commands.ghidra_trace_put_available()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_sessions(node: SessionContainer) -> None:
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Sessions'):
        commands.ghidra_trace_put_sessions()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_processes(node: ProcessContainer) -> None:
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Processes'):
        commands.ghidra_trace_put_processes()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_environment(node: Environment) -> None:
    """Refresh the environment descriptors (arch, os, endian)."""
    with commands.open_tracked_tx('Refresh Environment'):
        commands.ghidra_trace_put_environment()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_threads(node: ThreadContainer) -> None:
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        commands.ghidra_trace_put_threads()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_stack(node: Stack) -> None:
    """Refresh the backtrace for the thread."""
    tid = find_thread_by_stack_obj(node)
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()
        commands.ghidra_trace_activate()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values for the frame."""
    tid = find_thread_by_regs_obj(node)
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()
        commands.ghidra_trace_activate()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_mappings(node: Memory) -> None:
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        commands.ghidra_trace_put_regions()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_kmappings(node: KernelMemory) -> None:
    """Refresh the list of memory regions for the kernel."""
    with commands.open_tracked_tx('Refresh Kernel Memory Regions'):
        commands.ghidra_trace_put_kregions()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_modules(node: ModuleContainer):
    """Refresh the modules list for the process."""
    with commands.open_tracked_tx('Refresh Modules'):
        commands.ghidra_trace_put_modules()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_module(node: Module) -> None:
    """Refresh the module list for the process."""
    path = find_module_by_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Module'):
        commands.ghidra_trace_put_sections(path, addr)


@REGISTRY.method(action='refresh', display='refresh')
def refresh_kmodules(node: KernelModuleContainer) -> None:
    """Refresh the modules list for the process."""
    with commands.open_tracked_tx('Refresh Kernel Modules'):
        commands.ghidra_trace_put_kmodules()


@REGISTRY.method(action='refresh', display='refresh')
def refresh_dependencies(node: DependencyContainer) -> None:
    """Refresh the dependencies list for the module."""
    path = find_module_by_dependencies_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Dependencies'):
        commands.ghidra_trace_put_dependencies(path, addr)


@REGISTRY.method(action='refresh', display='refresh')
def refresh_exports(node: ExportContainer) -> None:
    """Refresh the exports list for the module."""
    path = find_module_by_exports_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Exports'):
        commands.ghidra_trace_put_exports(path, addr)


@REGISTRY.method(action='refresh', display='refresh')
def refresh_imports(node: ImportContainer) -> None:
    """Refresh the imports list for the module."""
    path = find_module_by_imports_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Imports'):
        commands.ghidra_trace_put_imports(path, addr)


@REGISTRY.method(action='refresh', display='refresh')
def refresh_sections(node: SectionContainer) -> None:
    """Refresh the sections list for the module."""
    path = find_module_by_sections_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Sections'):
        commands.ghidra_trace_put_sections(path, addr)


@REGISTRY.method(action='refresh', display='refresh')
def refresh_symbols(node: SymbolContainer) -> None:
    """Refresh the symbols list for the module."""
    path = find_module_by_symbols_obj(node)
    addr = util.get_module_address(path)
    path = "'"+path+"'"
    with commands.open_tracked_tx('Refresh Symbols'):
        commands.ghidra_trace_put_symbols(path, addr)


@REGISTRY.method(action='activate')
def activate_process(process: Process) -> None:
    """Switch to the process."""
    find_proc_by_obj(process)


@REGISTRY.method(action='activate')
def activate_thread(thread: Thread) -> None:
    """Switch to the thread."""
    find_thread_by_obj(thread)


@REGISTRY.method(action='activate')
def activate_frame(frame: StackFrame) -> None:
    """Select the frame."""
    find_frame_by_obj(frame)


@REGISTRY.method(action='delete')
def remove_process(process: Process) -> None:
    """Remove the process."""
    pid = find_proc_by_obj(process)
    util.targets[pid].detach()


@REGISTRY.method(action='attach', display='attach by pid')
def attach_obj(target: Attachable) -> None:
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    commands.attach_by_pid(pid)


@REGISTRY.method(action='attach', display='attach')
def attach_name(process: Process, name: str) -> None:
    """Attach the process to the given target."""
    commands.attach_by_name(name)


@REGISTRY.method()
def detach(process: Process) -> None:
    """Detach the process's target."""
    pid = find_proc_by_obj(process)
    util.targets[pid].detach()


@REGISTRY.method(action='launch', display='launch')
def launch(session: Session,
           file: Annotated[str, ParamDesc(display='file')],
           args: Annotated[str, ParamDesc(display='arguments')] = '',
           attach: Annotated[bool, ParamDesc(display='attach')] = True) -> None:
    """Run a native process with the given command line."""
    command = file
    if args != None:
        command += " "+args
    commands.ghidra_trace_create(command, attach)


@REGISTRY.method()
def kill(process: Process) -> None:
    """Kill execution of the process."""
    commands.ghidra_trace_kill()


@REGISTRY.method(action='resume')
def go(process: Process) -> None:
    """Continue execution of the process."""
    pid = find_proc_by_obj(process)
    dbg().resume(pid)


@REGISTRY.method()
def read_mem(process: Process, range: AddressRange) -> None:
    """Read memory."""
    # print("READ_MEM: process={}, range={}".format(process, range))
    nproc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        nproc, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        commands.putmem(offset_start, range.length())


@REGISTRY.method()
def write_mem(process: Process, address: Address, data: bytes) -> None:
    """Write memory."""
    pid = find_proc_by_obj(process)
    offset = process.trace.extra.require_mm().map_back(pid, address)
    with commands.open_tracked_tx('Write Memory'):
        commands.write_mem(offset, data)


@REGISTRY.method(display='intercept')
def intercept_export(function: Export, onEnter: str,
                     onLeave: Optional[str] = None,
                     callback: str = "on_message_print") -> None:
    """Intercept an exported function."""
    addr = find_export_by_obj(function)
    intercept(addr, onEnter, onLeave, callback)


@REGISTRY.method(display='intercept')
def intercept_import(function: Import, onEnter: str,
                     onLeave: Optional[str] = None,
                     callback: str = "on_message_print") -> None:
    """Intercept an imported function."""
    addr = find_import_by_obj(function)
    intercept(addr, onEnter, onLeave, callback)


@REGISTRY.method(display='intercept')
def intercept_symbol(function: Symbol, onEnter: str,
                     onLeave: Optional[str] = None,
                     callback: str = "on_message_print") -> None:
    """Intercept a function by symbol."""
    addr = find_symbol_by_obj(function)
    intercept(addr, onEnter, onLeave, callback)


def intercept(addr: str, onEnter: str, onLeave: Optional[str],
              callback: str) -> None:
    """Intercept a function."""
    name = util.current_state[addr]
    cmd = "Interceptor.attach(ptr('" + addr + "'), {"
    if onEnter.lower() != "none":
        cmd += addScript(onEnter)
    if onLeave != "":
        if onEnter.lower() != "none":
            cmd += ", "
        cmd += addScript(onLeave)
    cmd += "});"
    print(cmd)
    name = "intercept_" + name
    util.load_permanent_script(name, cmd, find_callback(callback))


sample = "code => {const cw = new X86Writer(code, { pc: ptr('$ADDR') }); cw.putNop(); cw.flush();}"


@REGISTRY.method(display='patch')
def patch_export(function: Export, addr: Address, size: int,
                 apply: str = sample) -> None:
    """Intercept an exported function."""
    addr = find_export_by_obj(function)
    patch(addr, size, apply)


@REGISTRY.method(display='patch')
def patch_import(function: Import, addr: Address, size: int,
                 apply: str = sample) -> None:
    """Intercept an imported function."""
    addr = find_import_by_obj(function)
    patch(addr, size, apply)


@REGISTRY.method(display='patch')
def patch_symbol(function: Symbol, addr: Address, size: int,
                 apply: str = sample) -> None:
    """Intercept a function by symbol."""
    addr = find_symbol_by_obj(function)
    patch(addr, size, apply)


@REGISTRY.method(display='patch')
def patch_memory(memory: Memory, addr: Address, size: int,
                 apply: str = sample) -> None:
    """Intercept a function by symbol."""
    patch(addr, size, apply)


def patch(addr: Address, size: Optional[int], apply: str,
          callback: str = "on_message_print") -> None:
    """Intercept a function."""
    if size is None:
        size = util.current_state[addr]
    if "$ADDR" in apply:
        apply = apply.replace("$ADDR", str(addr.offset))
    script = addScript(apply)
    cmd = "Memory.patchCode(ptr('" + str(addr.offset) + \
        "'), " + str(size) + ", " + script + ");"
    name = "path_" + str(addr.offset)
    util.run_script_no_ret(name, cmd, find_callback(callback))


@REGISTRY.method(display='watch')
def watch_region(region: MemoryRegion, addr: Address, size: int, onAccess: str,
                 callback: str = "on_message_print") -> None:
    """Watch an address range by region."""
    addr = find_region_by_obj(region)
    watch(addr, size, onAccess, callback)


@REGISTRY.method(display='watch')
def watch_module(module: Module, addr: Address, size: int, onAccess: str,
                 callback: str = "on_message_print") -> None:
    """Watch an address range by module."""
    path = find_module_by_obj(module)
    base = util.current_state[path]
    watch(addr, size, onAccess, callback)


@REGISTRY.method(display='watch')
def watch_section(section: Section, addr: Address, size: int, onAccess: str,
                  callback: str = "on_message_print") -> None:
    """Watch an address range by section."""
    addr = find_section_by_obj(section)
    watch(addr, size, onAccess, callback)


@REGISTRY.method(display='watch')
def watch_symbol(symbol: Symbol, addr: Address, size: int, onAccess: str,
                 callback: str = "on_message_print") -> None:
    """Watch an address range by symbol."""
    addr = find_symbol_by_obj(symbol)
    watch(addr, size, onAccess, callback)


def watch(addr: Address, size: int, onAccess: str, callback: str) -> None:
    """Watch an address range."""
    if size is None:
        size = util.current_state[addr]
    cmd = "MemoryAccessMonitor.enable({ base: ptr('" + str(addr) + "'), " + \
        " size: " + str(size) + " }, { "
    cmd += addScript(onAccess)
    cmd += "});"
    name = "watch_" + str(addr)
    util.load_permanent_script(name, cmd, find_callback(callback))


@REGISTRY.method(display='stalk')
def stalk(thread: Thread,
          onCallSummary: str,
          onReceive: Optional[str] = None,
          eventCall: bool = True,
          eventRet: bool = False,
          eventExec: bool = False,
          eventBlock: bool = False,
          eventCompile: bool = False,
          callback: str = "on_message_print") -> None:
    """Watch an address range by symbol."""
    tid = find_thread_by_obj(thread)
    cmd = "Stalker.follow(" + str(tid) + ", {" + \
        "   events: { " + \
        "      call: " + str(eventCall).lower() + "," + \
        "      ret: " + str(eventRet).lower() + "," + \
        "      exec: " + str(eventExec).lower() + "," + \
        "      block: " + str(eventBlock).lower() + "," + \
        "      compile: " + str(eventCompile).lower() + \
        "   }, "
    if onReceive is not None:
        cmd += addScript(onReceive)
    if onCallSummary is not None:
        if onReceive is not None:
            cmd += ", "
        cmd += addScript(onCallSummary)
    cmd += "});"
    name = "stalk" + str(tid)
    util.load_permanent_script(name, cmd, find_callback(callback))


@REGISTRY.method()
def sleep(process: Process, delay: int,
          callback: str = "on_message_print") -> None:
    """Put the current thread to sleep."""
    cmd = "Thread.sleep(" + str(delay) + ");"
    name = "sleep_" + str(util.selected_thread)
    util.run_script_no_ret(name, cmd, find_callback(callback))


@REGISTRY.method(display='scan')
def scan_memory(memory: Memory,
                addr: Address,
                size: int,
                pattern: str,
                stopOnMatch: bool = True) -> None:
    """Scan process memory."""
    scan("Memory", addr, size, pattern, stopOnMatch)


@REGISTRY.method(display='scan')
def scan_process_memory(process: Process,
                        addr: Address,
                        size: int,
                        pattern: str,
                        stopOnMatch: bool = True) -> None:
    """Scan process memory."""
    scan("Memory", addr, size, pattern, stopOnMatch)


@REGISTRY.method(display='scan')
def scan_kmemory(memory: KernelMemory,
                 addr: Address,
                 size: int,
                 pattern: str,
                 stopOnMatch: bool = True) -> None:
    """Scan kernel memory."""
    scan("Kernel", addr, size, pattern, stopOnMatch)


@REGISTRY.method(display='scan')
def scan_session_memory(session: Session,
                        addr: Address,
                        size: int,
                        pattern: str,
                        stopOnMatch: bool = True) -> None:
    """Scan kernel memory."""
    scan("Kernel", addr, size, pattern, stopOnMatch)


def scan(tag: str, addr: Address, size: int, pattern: str,
         stopOnMatch: bool) -> None:
    """Scan an address range."""
    if size is None:
        size = util.current_state[addr]
    ret = "  return 'stop'; " if stopOnMatch else ""
    cmd = tag + ".scan(" + \
        "ptr(" + str(addr.offset) + "), " + \
        str(size) + ", '" + pattern + "', " + \
        "{ onMatch(address, size) { " + \
        "    console.log('Found match at ', address); " + \
        ret +  \
        "  }," + \
        "  onComplete() { " + \
        "    console.log('scan complete'); " +\
        "  } " + \
        "});"
    name = "scan_" + str(addr)
    util.run_script_no_ret(name, cmd, None)


@REGISTRY.method()
def protect(memory: MemoryRegion,
            addr: Address,
            size: int,
            protection: str = 'rw-',
            callback: str = "on_message_print") -> None:
    """Change memory protections."""
    if size is None:
        size = util.current_state[addr]
    cmd = "Memory.protect(ptr('" + str(addr.offset) + "'), " + \
        str(size) + ", '" + protection + "');"
    name = "protect_" + str(addr.offset)
    util.run_script_no_ret(name, cmd, find_callback(callback))
    with commands.open_tracked_tx('Put Region'):
        commands.put_region(addr.offset)


@REGISTRY.method()
def kprotect(memory: KernelMemory,
             addr: Address,
             size: int,
             protection: str = 'rw-',
             callback: str = "on_message_print") -> None:
    """Change memory protections."""
    if size is None:
        size = util.current_state[addr]
    cmd = "Kernel.protect(ptr('" + str(addr.offset) + "'), " + \
        str(size) + ", '" + protection + "');"
    name = "protect_" + str(addr.offset)
    util.run_script_no_ret(name, cmd, find_callback(callback))


@REGISTRY.method()
def load(module: Module,
         callback: str = "on_message_print") -> None:
    """Load module."""
    path = find_module_by_obj(module)
    cmd = "Module.load('" + path + "');"
    name = "load_" + path
    util.run_script_no_ret(name, cmd, find_callback(callback))


@REGISTRY.method()
def init(module: Module,
         callback: str = "on_message_print"):
    """Ensure module is initialized."""
    path = find_module_by_obj(module)
    cmd = "Module.ensureInitialized('" + path + "');"
    name = "load_" + path
    util.run_script_no_ret(name, cmd, find_callback(callback))


@REGISTRY.method()
def echo(process: Process,
         msg: Annotated[str, ParamDesc(display='message')],
         callback: str = "on_message_print"):
    """Ensure module is initialized."""
    cmd = "result = '" + msg + "';"
    name = "echo"
    util.run_script(name, cmd, find_callback(callback))


def find_callback(callback: str):
    if callback is not None:
        return getattr(util, callback)


def addScript(textOrFile):
    res = ""
    if textOrFile is None:
        return res
    try:
        fileOL = open(textOrFile, "r")
        for l in fileOL.readlines():
            res += l
        fileOL.close()
    except Exception:
        res += textOrFile
    return res


def dbg():
    return util.dbg._base
