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
import code
from contextlib import contextmanager
import inspect
import json
import os.path
import re
import socket
import sys
import time
from typing import (Any, Callable, Dict, Generator, List, Optional, Sequence,
                    Tuple, Type, TypeVar, Union)

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, Schedule, Trace, TraceObject, Transaction

import frida  # type: ignore
from frida.core import Session

from . import util, arch, methods

PAGE_SIZE = 4096

SESSIONS_PATH = 'Sessions'
SESSION_KEY_PATTERN = '[{sid}]'
SESSION_PATTERN = SESSIONS_PATH + SESSION_KEY_PATTERN
ATTRIBUTES_PATH = SESSION_PATTERN + '.Attributes'
AVAILABLES_PATH = SESSION_PATTERN + '.Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
APPLICATIONS_PATH = SESSION_PATTERN + '.Applications'
APPLICATION_KEY_PATTERN = '[{pid}]'
APPLICATION_PATTERN = APPLICATIONS_PATH + APPLICATION_KEY_PATTERN
PROCESSES_PATH = SESSION_PATTERN + '.Processes'
PROCESS_KEY_PATTERN = '[{pid}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
ENV_PATTERN = SESSION_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tid}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
FRAMES_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = FRAMES_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = THREAD_PATTERN + '.Registers'
REGIONS_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start}]'
REGION_PATTERN = REGIONS_PATTERN + REGION_KEY_PATTERN
KREGIONS_PATTERN = SESSION_PATTERN + '.Memory'
KREGION_KEY_PATTERN = '[{start}]'
KREGION_PATTERN = KREGIONS_PATTERN + KREGION_KEY_PATTERN
HEAP_PATTERN = PROCESS_PATTERN + '.Heap'
HEAP_REGION_KEY_PATTERN = '[{start}]'
HEAP_REGION_PATTERN = HEAP_PATTERN + HEAP_REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
KMODULES_PATTERN = SESSION_PATTERN + '.Modules'
KMODULE_KEY_PATTERN = '[{modpath}]'
KMODULE_PATTERN = KMODULES_PATTERN + KMODULE_KEY_PATTERN
SECTIONS_PATTERN = MODULE_PATTERN + '.Sections'
SECTION_KEY_PATTERN = '[{start}]'
SECTION_PATTERN = SECTIONS_PATTERN + SECTION_KEY_PATTERN
IMPORTS_PATTERN = MODULE_PATTERN + '.Imports'
IMPORT_KEY_PATTERN = '[{addr}]'
IMPORT_PATTERN = IMPORTS_PATTERN + IMPORT_KEY_PATTERN
EXPORTS_PATTERN = MODULE_PATTERN + '.Exports'
EXPORT_KEY_PATTERN = '[{addr}]'
EXPORT_PATTERN = EXPORTS_PATTERN + EXPORT_KEY_PATTERN
SYMBOLS_PATTERN = MODULE_PATTERN + '.Symbols'
SYMBOL_KEY_PATTERN = '[{addr}]'
SYMBOL_PATTERN = SYMBOLS_PATTERN + SYMBOL_KEY_PATTERN
DEPENDENCIES_PATTERN = MODULE_PATTERN + '.Dependencies'
DEPENDENCY_KEY_PATTERN = '[{name}]'
DEPENDENCY_PATTERN = DEPENDENCIES_PATTERN + DEPENDENCY_KEY_PATTERN
CLASSES_PATTERN = PROCESS_PATTERN + '.Classes'
CLASS_KEY_PATTERN = '[{path}]'
CLASS_PATTERN = CLASSES_PATTERN + CLASS_KEY_PATTERN
METHODS_PATTERN = CLASS_PATTERN + '.Methods'
METHOD_KEY_PATTERN = '[{name}]'
METHOD_PATTERN = METHODS_PATTERN + METHOD_KEY_PATTERN
LOADERS_PATTERN = PROCESS_PATTERN + '.ClassLoaders'
LOADER_KEY_PATTERN = '[{path}]'
LOADER_PATTERN = LOADERS_PATTERN + LOADER_KEY_PATTERN

# TODO: Symbols


class Extra(object):
    def __init__(self) -> None:
        self.memory_mapper: Optional[arch.DefaultMemoryMapper] = None
        self.register_mapper: Optional[arch.DefaultRegisterMapper] = None

    def require_mm(self) -> arch.DefaultMemoryMapper:
        if self.memory_mapper is None:
            raise RuntimeError("No memory mapper")
        return self.memory_mapper

    def require_rm(self) -> arch.DefaultRegisterMapper:
        if self.register_mapper is None:
            raise RuntimeError("No register mapper")
        return self.register_mapper


class ErrorWithCode(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self) -> str:
        return repr(self.code)


class State(object):

    def __init__(self) -> None:
        self.reset_client()

    def require_client(self) -> Client:
        if self.client is None:
            raise RuntimeError("Not connected")
        return self.client

    def require_no_client(self) -> None:
        if self.client != None:
            raise RuntimeError("Already connected")

    def reset_client(self) -> None:
        self.client: Optional[Client] = None
        self.reset_trace()

    def require_trace(self) -> Trace[Extra]:
        if self.trace is None:
            raise RuntimeError("No trace active")
        return self.trace

    def require_no_trace(self) -> None:
        if self.trace != None:
            raise RuntimeError("Trace already started")

    def reset_trace(self) -> None:
        self.trace: Optional[Trace[Extra]] = None
        util.set_convenience_variable('_ghidra_tracing', "false")
        self.reset_tx()

    def require_tx(self) -> Tuple[Trace, Transaction]:
        trace = self.require_trace()
        if self.tx is None:
            raise RuntimeError("No transaction")
        return trace, self.tx

    def require_no_tx(self) -> None:
        if self.tx != None:
            raise RuntimeError("Transaction already started")

    def reset_tx(self) -> None:
        self.tx: Optional[Transaction] = None


STATE = State()


def ghidra_trace_connect(address: Optional[str]) -> None:
    """
    Connect Python to Ghidra for tracing

    Address must be of the form 'host:port'
    """

    STATE.require_no_client()
    if address is None:
        raise RuntimeError(
            "'ghidra_trace_connect': missing required argument 'address'")

    parts = address.split(':')
    if len(parts) != 2:
        raise RuntimeError("address must be in the form 'host:port'")
    host, port = parts
    try:
        c = socket.socket()
        c.connect((host, int(port)))
        # TODO: Can we get version info from the DLL?
        STATE.client = Client(c, "frida", methods.REGISTRY)
        print(f"Connected to {STATE.client.description} at {address}")
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_listen(address: str = '0.0.0.0:0') -> None:
    """
    Listen for Ghidra to connect for tracing

    Takes an optional address for the host and port on which to listen. Either
    the form 'host:port' or just 'port'. If omitted, it will bind to an
    ephemeral port on all interfaces. If only the port is given, it will bind to
    that port on all interfaces. This command will block until the connection is
    established.
    """

    STATE.require_no_client()
    parts = address.split(':')
    if len(parts) == 1:
        host, port = '0.0.0.0', parts[0]
    elif len(parts) == 2:
        host, port = parts
    else:
        raise RuntimeError("address must be 'port' or 'host:port'")

    try:
        s = socket.socket()
        s.bind((host, int(port)))
        host, port = s.getsockname()
        s.listen(1)
        print("Listening at {}:{}...".format(host, port))
        c, (chost, cport) = s.accept()
        s.close()
        print("Connection from {}:{}".format(chost, cport))
        STATE.client = Client(c, "frida", methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect() -> None:
    """Disconnect Python from Ghidra for tracing"""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name(progname: Optional[str]) -> str:
    if progname is None:
        return 'frida/noname'
    return 'frida/' + re.split(r'/|\\', progname)[-1]


def start_trace(name: str) -> None:
    language, compiler = arch.compute_ghidra_lcsp()
    trace = STATE.require_client().create_trace(
        name, language, compiler, extra=Extra())
    # TODO: Is adding an attribute like this recommended in Python?
    trace.extra.memory_mapper = arch.compute_memory_mapper(language)
    trace.extra.register_mapper = arch.compute_register_mapper(language)

    frame = inspect.currentframe()
    if frame is None:
        raise AssertionError("cannot locate schema.xml")
    parent = os.path.dirname(inspect.getfile(frame))
    schema_fn = os.path.join(parent, 'schema.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with trace.open_tx("Create Root Object"):
        root = trace.create_root_object(schema_xml, 'FridaRoot')
        root.set_value('_display', util.DBG_VERSION + ' via frida')
    util.set_convenience_variable('_ghidra_tracing', "true")
    STATE.trace = trace


def ghidra_trace_start(name: Optional[str] = None) -> None:
    """Start a Trace in Ghidra"""

    STATE.require_client()
    name = compute_name(name)
    STATE.require_no_trace()
    start_trace(name)


def ghidra_trace_stop() -> None:
    """Stop the Trace in Ghidra"""

    STATE.require_trace().close()
    STATE.reset_trace()


def ghidra_trace_restart(name: Optional[str] = None) -> None:
    """Restart or start the Trace in Ghidra"""

    STATE.require_client()
    trace = STATE.require_trace()
    if trace != None:
        trace.close()
        STATE.reset_trace()
    name = compute_name(name)
    start_trace(name)


def attach_by_name(name: str) -> Session:
    """
    Attach to a target.
    """

    dbg = util.dbg
    keys = []
    processes = dbg.enumerate_processes(scope="full")  # type: ignore
    for proc in processes:
        if proc.name == name:
            target: Session = dbg.attach(proc.pid)  # type: ignore
            trace, tx = STATE.require_tx()
            with trace.open_tx('Attach By Name') as tx:
                put_process(keys, proc)
                trace.proxy_object_path(
                    PROCESSES_PATH).retain_values(keys)
                util.processes[proc.pid] = proc
                util.targets[proc.pid] = target
                return target


def attach_by_pid(pid: int) -> Session:
    """
    Attach to a target.
    """

    dbg = util.dbg
    keys = []
    processes = dbg.enumerate_processes(scope="full")  # type: ignore
    for proc in processes:
        if proc.pid == pid:
            target = dbg.attach(pid)  # type: ignore
            trace = STATE.require_trace()
            with trace.open_tx('Attach By Pid') as tx:
                put_process(keys, proc)
                trace.proxy_object_path(
                    PROCESSES_PATH).retain_values(keys)
                util.processes[proc.pid] = proc
                util.targets[proc.pid] = target
                return target
    return None


def ghidra_trace_create(command: Optional[str] = None, attach: bool = False) -> Session:
    """
    Create a target.
    """

    dbg = util.dbg
    pid = dbg.spawn(command)  # type: ignore
    util.select_process(pid)
    trace = STATE.require_trace()
    with trace.open_tx('Initial Snap') as tx:
        trace.snapshot("Initial Snapshot")
    if attach:
        return attach_by_pid(pid)
    return None


def attach_by_device(id: int) -> None:
    """
    Attach to a device.
    """

    util.dbg = util.GhidraDbg(id)
    ghidra_trace_connect(os.getenv('GHIDRA_TRACE_RMI_ADDR'))
    # args = os.getenv('OPT_TARGET_ARGS')
    # if args:
    #    args = ' ' + args
    ghidra_trace_start(os.getenv('OPT_TARGET_IMG'))
    # ghidra_trace_create(
    #    os.getenv('OPT_TARGET_IMG') + args, attach=True)
    repl()


def ghidra_trace_kill() -> None:
    """
    Kill a session.
    """

    dbg = util.dbg
    dbg.kill(util.selected_process())  # type: ignore


def ghidra_trace_info() -> None:
    """Get info about the Ghidra connection"""

    if STATE.client is None:
        print("Not connected to Ghidra")
        return
    host, port = STATE.client.s.getpeername()
    print(f"Connected to {STATE.client.description} at {host}:{port}")
    if STATE.trace is None:
        print("No trace")
        return
    print("Trace active")


def ghidra_trace_info_lcsp() -> None:
    """
    Get the selected Ghidra language-compiler-spec pair. 
    """

    language, compiler = arch.compute_ghidra_lcsp()
    print("Selected Ghidra language: {}".format(language))
    print("Selected Ghidra compiler: {}".format(compiler))


def ghidra_trace_txstart(description: str = "tx") -> None:
    """
    Start a transaction on the trace
    """

    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


def ghidra_trace_txcommit():
    """
    Commit the current transaction
    """

    STATE.require_tx()[1].commit()
    STATE.reset_tx()


def ghidra_trace_txabort() -> None:
    """
    Abort the current transaction

    Use only in emergencies.
    """

    trace, tx = STATE.require_tx()
    print("Aborting trace transaction!")
    tx.abort()
    STATE.reset_tx()


@contextmanager
def open_tracked_tx(description: str) -> Generator[Transaction, None, None]:
    with STATE.require_trace().open_tx(description) as tx:
        STATE.tx = tx
        yield tx
    STATE.reset_tx()


def ghidra_trace_save() -> None:
    """
    Save the current trace
    """

    STATE.require_trace().save()


def ghidra_trace_new_snap(description: Optional[str] = None,
                          time: Optional[Schedule] = None) -> Dict[str, int]:
    """
    Create a new snapshot

    Subsequent modifications to machine state will affect the new snapshot.
    """

    description = str(description)
    trace, tx = STATE.require_tx()
    return {'snap': STATE.require_trace().snapshot(description)}


def ghidra_trace_set_snap(snap: int) -> None:
    """
    Go to a snapshot

    Subsequent modifications to machine state will affect the given snapshot.
    """

    trace, tx = STATE.require_tx()
    trace.extra.set_snap(snap)


def quantize_pages(start: int, end: int):
    return (start // PAGE_SIZE * PAGE_SIZE, (end+PAGE_SIZE-1) // PAGE_SIZE*PAGE_SIZE)


def eval_address(address: Union[str, int]) -> int:
    try:
        return util.parse_and_eval(address)
    except Exception:
        raise RuntimeError("Cannot convert '{}' to address".format(address))


def eval_range(address: Union[str, int],
               length: Union[str, int]) -> Tuple[int, int]:
    start = eval_address(address)
    if isinstance(start, str):
        start = int(start)
    try:
        len = util.parse_and_eval(length)
        if isinstance(len, str):
            len = int(len)
        end = start + len
    except Exception as e:
        raise RuntimeError("Cannot convert '{}' to length".format(length))
    return start, end


last_address = 0
last_length = 4096


def put_mem_callback(message: dict[str, Any], data: Any):
    trace = STATE.require_trace()
    pid = util.selected_process()
    if pid is None:
        return
    values = get_values_from_callback(message, data)
    if not isinstance(values, str):
        return
    start = get_data_from_callback(message, data)
    if not isinstance(start, int):
        return
    if type(values) is dict:
        putmem_state(last_address, last_address+last_length, 'error')
        return {'count': 0}

    buf = []
    for l in values.split("\n"):
        split = l.split(" ")
        for i in range(2, 18):
            buf.append(int(split[i], 16))
    if buf != None:
        base, addr = trace.extra.require_mm().map(pid, start)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        count = trace.put_bytes(addr, bytes(buf))
        return {'count': count}


def putmem(address, length) -> None:
    global last_address
    global last_length
    if address is None:
        return
    if isinstance(address, int):
        address = str(address)
    if isinstance(length, int):
        length = str(length)
    last_address = int(address, 0)
    last_length = int(length)

    cmd = "var buf = ptr(" + address + ").readByteArray(" + \
        length + "); result = hexdump(buf, {header:false});"
    util.run_script_with_data("read_memory", cmd, address, put_mem_callback)


def ghidra_trace_putmem(address, length, pages=True) -> None:
    """
    Record the given block of memory into the Ghidra trace.
    """

    trace, tx = STATE.require_tx()
    if length < PAGE_SIZE:
        length = PAGE_SIZE
    return putmem(address, length)


def write_mem(address, buf) -> None:
    # TODO: UNTESTED
    if isinstance(address, int):
        address = str(address)
    length = len(buf)
    cmd = "var buf = [];  var str = '" + str(buf) + "'; var len = " + str(length) + "; " + \
        "for (var i = 0; i < len; ++i) {" + \
        "  var code = str.charCodeAt(i);" + \
        "  buf = buf.concat([code]);" + \
        "}; " + \
        "ptr('"+address+"').writeByteArray(buf);"
    util.run_script("write_memory", cmd, util.on_message_print)


def putmem_state(address, length, state, pages=True) -> None:
    trace = STATE.require_trace()
    trace.validate_state(state)
    start, end = eval_range(address, length)
    if pages:
        start, end = quantize_pages(start, end)
    pid = util.selected_process()
    if pid is None:
        return
    base, addr = trace.extra.require_mm().map(pid, start)
    if base != addr.space and state != 'unknown':
        trace.create_overlay_space(base, addr.space)
    trace.set_memory_state(addr.extend(end - start), state)


def ghidra_trace_putmem_state(address, length, state, pages=True) -> None:
    """
    Set the state of the given range of memory in the Ghidra trace.
    """

    trace, tx = STATE.require_tx()
    return putmem_state(address, length, state, pages)


def ghidra_trace_delmem(address, length) -> None:
    """
    Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages by
    default, usually to take advantage of spatial locality. This command does
    not quantize. You must do that yourself, if necessary.
    """

    trace, tx = STATE.require_tx()
    start, end = eval_range(address, length)
    pid = util.selected_process()
    base, addr = trace.extra.require_mm().map(pid, start)
    # Do not create the space. We're deleting stuff.
    trace.delete_bytes(addr.extend(end - start))


def put_reg_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    tid = util.selected_thread()
    context = None
    for t in values:
        if t['id'] == tid:
            context = t['context']
            break
    if context is None:
        return

    space = REGS_PATTERN.format(sid=sid, pid=pid, tid=tid)
    trace = STATE.require_trace()
    trace.create_overlay_space('register', space)
    regs = trace.create_object(space)
    regs.insert()
    mapper = trace.extra.require_rm()
    values = []
    for r in context.keys():
        rval = context[r]
        try:
            values.append(mapper.map_value(pid, r, int(rval, 0)))
            regs.set_value(r, rval)
        except Exception as e:
            print(f"{e}")
            pass
    trace.put_registers(space, values)


def putreg() -> None:
    cmd = "result = Process.enumerateThreads();"
    util.run_script("list_threads", cmd, put_reg_callback)


def ghidra_trace_putreg() -> None:
    """
    Record the given register group for the current frame into the Ghidra trace.

    If no group is specified, 'all' is assumed.
    """

    trace, tx = STATE.require_tx()
    return putreg()


def ghidra_trace_create_obj(path: str) -> None:
    """
    Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra_trace_insert-obj' to finish the
    object, after all its required attributes are set.
    """

    trace, tx = STATE.require_tx()
    obj = trace.create_object(path)
    obj.insert()
    print("Created object: id={}, path='{}'".format(obj.id, obj.path))


def ghidra_trace_insert_obj(path) -> None:
    """
    Insert an object into the Ghidra trace.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    trace, tx = STATE.require_tx()
    span = trace.proxy_object_path(path).insert()
    print("Inserted object: lifespan={}".format(span))


def ghidra_trace_remove_obj(path) -> None:
    """
    Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree for the
    current snap and onwards.
    """

    trace, tx = STATE.require_tx()
    trace.proxy_object_path(path).remove()


def to_bytes(value):
    return bytes(ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value)))


def to_string(value, encoding):
    b = bytes(ord(value[i]) if type(value[i]) == str else int(
        value[i]) for i in range(0, len(value)))
    return str(b, encoding)


def to_bool_list(value):
    return [bool(value[i]) for i in range(0, len(value))]


def to_int_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_short_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_string_list(value, encoding):
    return [to_string(value[i], encoding) for i in range(0, len(value))]


def eval_value(value: Any, schema: Optional[sch.Schema] = None) -> Tuple[Union[
        bool, int, float, bytes, Tuple[str, Address], List[bool], List[int],
        List[str], str], Optional[sch.Schema]]:
    if schema == sch.CHAR or schema == sch.BYTE or schema == sch.SHORT or schema == sch.INT or schema == sch.LONG or schema == None:
        value = util.parse_and_eval(value)
        return value, schema
    if schema == sch.ADDRESS:
        value = util.parse_and_eval(value)
        pid = util.selected_process()
        if pid is None:
            pid = 0
        trace = STATE.require_trace()
        base, addr = trace.extra.require_mm().map(pid, value)
        return (base, addr), sch.ADDRESS
    if type(value) != str:
        value = eval("{}".format(value))
    if schema == sch.BOOL_ARR:
        return to_bool_list(value), schema
    if schema == sch.BYTE_ARR:
        return to_bytes(value), schema
    if schema == sch.SHORT_ARR:
        return to_short_list(value), schema
    if schema == sch.INT_ARR:
        return to_int_list(value), schema
    if schema == sch.LONG_ARR:
        return to_int_list(value), schema
    if schema == sch.STRING_ARR:
        return to_string_list(value, 'utf-8'), schema
    if schema == sch.CHAR_ARR:
        return to_string(value, 'utf-8'), sch.CHAR_ARR
    if schema == sch.STRING:
        return to_string(value, 'utf-8'), sch.STRING

    return value, schema


def ghidra_trace_set_value(path: str, key: str, value: Any,
                           schema: Optional[str] = None) -> None:
    """
    Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal. 
    NOTE: The type of an expression may be subject to the dbgeng's current 
    language. which current defaults to DEBUG_EXPR_CPLUSPLUS (vs DEBUG_EXPR_MASM). 
    For most non-primitive cases, we are punting to the Python API.
    """
    real_schema = None if schema is None else sch.Schema(schema)
    trace, tx = STATE.require_tx()
    if schema == sch.OBJECT:
        val = trace.proxy_object_path(value)
    else:
        val, real_schema = eval_value(value, real_schema)
        if real_schema == sch.ADDRESS and isinstance(val, tuple):
            base, addr = val
            val = addr
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
    trace.proxy_object_path(path).set_value(key, val, real_schema)


def ghidra_trace_retain_values(path: str, keys: str) -> None:
    """
    Retain only those keys listed, settings all others to null.

    Takes a list of keys to retain. The first argument may optionally be one of
    the following:

        --elements To set all other elements to null (default)
        --attributes To set all other attributes to null
        --both To set all other values (elements and attributes) to null

    If, for some reason, one of the keys to retain would be mistaken for this
    switch, then the switch is required. Only the first argument is taken as the
    switch. All others are taken as keys.
    """

    key_list = keys.split(" ")

    trace, tx = STATE.require_tx()
    kinds = 'elements'
    if key_list[0] == '--elements':
        kinds = 'elements'
        key_list = key_list[1:]
    elif key_list[0] == '--attributes':
        kinds = 'attributes'
        key_list = key_list[1:]
    elif key_list[0] == '--both':
        kinds = 'both'
        key_list = key_list[1:]
    elif key_list[0].startswith('--'):
        raise RuntimeError("Invalid argument: " + key_list[0])
    trace.proxy_object_path(path).retain_values(key_list, kinds=kinds)


def ghidra_trace_get_obj(path: str) -> None:
    """
    Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm whether an
    object exists and provide its id.
    """

    trace = STATE.require_trace()
    object = trace.get_object(path)
    print("{}\t{}".format(object.id, object.path))


class TableColumn(object):
    def __init__(self, head):
        self.head = head
        self.contents = [head]
        self.is_last = False

    def add_data(self, data):
        self.contents.append(str(data))

    def finish(self):
        self.width = max(len(d) for d in self.contents) + 1

    def print_cell(self, i):
        print(
            self.contents[i] if self.is_last else self.contents[i].ljust(self.width), end='')


class Tabular(object):
    def __init__(self, heads):
        self.columns = [TableColumn(h) for h in heads]
        self.columns[-1].is_last = True
        self.num_rows = 1

    def add_row(self, datas):
        for c, d in zip(self.columns, datas):
            c.add_data(d)
        self.num_rows += 1

    def print_table(self):
        for c in self.columns:
            c.finish()
        for rn in range(self.num_rows):
            for c in self.columns:
                c.print_cell(rn)
            print('')


def val_repr(value: Any):
    if isinstance(value, TraceObject):
        return value.path
    elif isinstance(value, Address):
        return '{}:{:08x}'.format(value.space, value.offset)
    return repr(value)


def print_values(values: Any) -> None:
    table = Tabular(['Parent', 'Key', 'Span', 'Value', 'Type'])
    for v in values:
        table.add_row(
            [v.parent.path, v.key, v.span, val_repr(v.value), v.schema])
    table.print_table()


def ghidra_trace_get_values(pattern: str) -> None:
    """
    List all values matching a given path pattern.
    """

    trace = STATE.require_trace()
    values = trace.get_values(pattern)
    print_values(values)


def ghidra_trace_get_values_rng(address: Union[str, int],
                                length: Union[str, int]) -> None:
    """
    List all values intersecting a given address range.
    """

    trace = STATE.require_trace()
    start, end = eval_range(address, length)
    pid = util.selected_process()
    if pid is None:
        return
    base, addr = trace.extra.require_mm().map(pid, start)
    # Do not create the space. We're querying. No tx.
    values = trace.get_values_intersecting(addr.extend(end - start))
    print_values(values)


def activate(path: Optional[str] = None) -> None:
    trace = STATE.require_trace()
    if path is None:
        pid = util.selected_process()
        if pid is None:
            path = PROCESSES_PATH
        else:
            tid = util.selected_thread()
            if tid is None:
                path = PROCESS_PATTERN.format(sid='local', pid=pid)
            else:
                path = THREAD_PATTERN.format(sid='local', pid=pid, tid=tid)
    trace.proxy_object_path(path).activate()


def ghidra_trace_activate(path: Optional[str] = None) -> None:
    """
    Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If path is
    omitted, this will activate the current frame.
    """

    activate(path)


def ghidra_trace_disassemble(address: Union[str, int]) -> None:
    """
    Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or unknown
    memory encountered.
    """

    trace, tx = STATE.require_tx()
    start = eval_address(address)
    pid = util.selected_process()
    base, addr = trace.extra.require_mm().map(pid, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = trace.disassemble(addr)
    print("Disassembled {} bytes".format(length))


def put_sessions() -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    trace = STATE.require_trace()
    result = frida.enumerate_devices()
    for d in result:
        id = d.id
        name = d.name
        type = d.type
        dpath = SESSION_PATTERN.format(sid=id)
        procobj = trace.create_object(dpath)
        keys.append(SESSION_KEY_PATTERN.format(sid=id))
        procobj.set_value('Id', id)
        procobj.set_value('Name', name)
        procobj.set_value('Type', type)
        procobj.set_value('_display', '{}:{}'.format(id, name))
        procobj.insert()
        trace.create_object(AVAILABLES_PATH.format(sid=id)).insert()
    trace.proxy_object_path(SESSIONS_PATH).retain_values(keys)


def ghidra_trace_put_sessions() -> None:
    """
    Put the list of devices into the trace's Sessions list.
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_sessions()


def compute_proc_state(pid: Optional[int] = None) -> str:
    return 'STOPPED'


def put_process(keys, proc) -> None:
    radix = util.get_convenience_variable('output-radix')
    pid = proc.pid
    ppath = PROCESS_PATTERN.format(sid='local', pid=pid)
    keys.append(PROCESS_KEY_PATTERN.format(pid=pid))
    trace = STATE.require_trace()
    procobj = trace.create_object(ppath)

    state = compute_proc_state(pid)
    procobj.set_value('State', state)
    pidstr = ('0x{:x}' if radix ==
              16 else '0{:o}' if radix == 8 else '{}').format(pid)
    procobj.set_value('PIDS', pid)
    procobj.set_value('Name', proc.name)
    procobj.set_value('_display', '{} {}'.format(pidstr, proc.name))
    trace.create_object(ppath+".Memory").insert()
    trace.create_object(ppath+".Modules").insert()
    trace.create_object(ppath+".Threads").insert()
    procobj.insert()


def put_processes(running: bool = False) -> None:

    if running:
        return

    keys = []
    # Set running=True to avoid process changes, even while stopped
    for i in util.processes.keys():
        p = util.processes[i]
        put_process(keys, p)
    trace = STATE.require_trace()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


def put_state(event_process: int) -> None:
    ipath = PROCESS_PATTERN.format(pid=event_process)
    trace = STATE.require_trace()
    procobj = trace.create_object(ipath)
    state = compute_proc_state(event_process)
    procobj.set_value('State', state)
    procobj.insert()
    tid = util.selected_thread()
    if tid is not None:
        ipath = THREAD_PATTERN.format(pid=event_process, tid=tid)
        threadobj = trace.create_object(ipath)
        threadobj.set_value('State', state)
        threadobj.insert()


def ghidra_trace_put_processes() -> None:
    """
    Put the list of processes into the trace's Processes list.
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_processes()


def put_available() -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    trace = STATE.require_trace()
    result = util.dbg.enumerate_processes()  # type: ignore
    for p in result:
        id = p.pid
        name = p.name
        ppath = AVAILABLE_PATTERN.format(sid='local', pid=id)
        procobj = trace.create_object(ppath)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=id))
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(id)
        procobj.set_value('PID', id)
        procobj.set_value('Name', name)
        procobj.set_value('_display', '{} {}'.format(pidstr, name))
        procobj.insert()
    trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


def ghidra_trace_put_available() -> None:
    """
    Put the list of available processes into the trace's Available list.
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_available()


def put_applications() -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    trace = STATE.require_trace()
    result = util.dbg.enumerate_applications()  # type: ignore
    for p in result:
        id = p.pid
        name = p.name
        ppath = APPLICATION_PATTERN.format(sid='local', pid=id)
        procobj = trace.create_object(ppath)
        keys.append(APPLICATION_KEY_PATTERN.format(pid=id))
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(id)
        procobj.set_value('PID', id)
        procobj.set_value('Name', name)
        procobj.set_value('_display', '{} {}'.format(pidstr, name))
        procobj.insert()
    trace.proxy_object_path(APPLICATIONS_PATH).retain_values(keys)


def ghidra_trace_put_applications() -> None:
    """
    Put the list of available applications into the trace's Available list.
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_applications()


def put_session_attributes_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    apath = ATTRIBUTES_PATH.format(sid=sid)
    aobj = trace.create_object(apath)
    for v in values.keys():
        aobj.set_value(v, values[v])
    aobj.insert()


def put_session_attributes() -> None:
    cmd = "var d = {};" + \
        "d['version'] = Frida.version;" + \
        "d['heapSize'] = Frida.heapSize;" + \
        "d['id'] = Process.id;" + \
        "d['arch'] = Process.arch;" + \
        "d['os'] = Process.platform;" + \
        "d['pageSize'] = Process.pageSize;" + \
        "d['pointerSize'] = Process.pointerSize;" + \
        "d['codeSigning'] = Process.codeSigningPolicy;" + \
        "d['debugger'] = Process.isDebuggerAttached();" + \
        "d['runtime'] = Script.runtime;" + \
        "d['kernel'] = Kernel.available;" + \
        "if (Kernel.available) {" + \
        "   d['kbase'] = Kernel.base;" + \
        "   d['kPageSize'] = Kernel.pageSize;" + \
        "}" + \
        "result = d;"
    util.run_script("get_session_attributeds", cmd,
                    put_session_attributes_callback)


def ghidra_trace_put_session_attributes() -> None:
    """
    Put some environment indicators into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_session_attributes()


def put_environment() -> None:
    sid = util.selected_session()
    epath = ENV_PATTERN.format(sid=sid)
    trace = STATE.require_trace()
    envobj = trace.create_object(epath)
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('Endian', arch.get_endian())
    envobj.set_value('Debugger', 'frida')
    params = util.dbg.query_system_parameters()  # type: ignore
    for k in params.keys():
        v = params[k]
        if isinstance(v, dict):
            for kk in v.keys():
                vv = v[kk]
                envobj.set_value(k+":"+kk, v[kk])
        else:
            envobj.set_value(k, params[k])

    envobj.insert()


def ghidra_trace_put_environment() -> None:
    """
    Put some environment indicators into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()


def put_region_callback(message: dict[str, Any], data: Any) -> None:
    r = get_values_from_callback(message, data)
    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return

    base = r['base']
    size = r['size']
    prot = r['protection']
    rpath = REGION_PATTERN.format(sid=sid, pid=pid, start=base)
    trace = STATE.require_trace()
    robj = trace.create_object(rpath)

    mapper = trace.extra.require_mm()
    base_base, base_addr = mapper.map(pid, int(base, 0))
    if base_base != base_addr.space:
        trace.create_overlay_space(base_base, base_addr.space)
    robj.set_value('Range', base_addr.extend(size))
    util.current_state[base] = size
    robj.set_value('Protection', prot)
    if 'file' in r.keys():
        file = r['file']
        fpath = file['path']
        foffset = file['offset']
        fsize = file['size']
        robj.set_value('File', '{} {:x}:{:x}'.format(fpath, foffset, fsize))
    robj.set_value('_display', '{}:{:x} {} '.format(base, size, prot))
    robj.insert()


def put_region(address) -> None:
    cmd = "result = Process.findRangeByAddress(ptr(" + str(address) + "));"
    util.run_script("find_range", cmd, put_region_callback)


def put_regions_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for r in values:
        # print(f"R={r}")
        base = r['base']
        size = r['size']
        prot = r['protection']
        rpath = REGION_PATTERN.format(sid=sid, pid=pid, start=base)
        robj = trace.create_object(rpath)
        keys.append(REGION_KEY_PATTERN.format(start=base))

        base_base, base_addr = mapper.map(pid, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        robj.set_value('Range', base_addr.extend(size))
        util.current_state[base] = size
        robj.set_value('Protection', prot)
        if 'file' in r.keys():
            file = r['file']
            fpath = file['path']
            foffset = file['offset']
            fsize = file['size']
            robj.set_value('File', '{} {:x}:{:x}'.format(
                fpath, foffset, fsize))
        robj.set_value('_display', '{}:{:x} {} '.format(base, size, prot))
        robj.insert()
    trace.proxy_object_path(
        REGIONS_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_regions(running=False) -> None:
    if running:
        return
    cmd = "result = Process.enumerateRanges('---');"
    util.run_script("list_ranges", cmd, put_regions_callback)


def ghidra_trace_put_regions() -> None:
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_regions()


def put_kregions_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for r in values:
        # print(f"R={r}")
        base = r['base']
        size = r['size']
        prot = r['protection']
        rpath = KREGION_PATTERN.format(sid=sid, pid=pid, start=base)
        robj = trace.create_object(rpath)
        keys.append(KREGION_KEY_PATTERN.format(start=base))

        base_base, base_addr = mapper.map(pid, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        robj.set_value('Range', base_addr.extend(size))
        util.current_state[base] = size
        robj.set_value('Protection', prot)
        robj.set_value('_display', '{}:{:x} {} '.format(base, size, prot))
        robj.insert()
    trace.proxy_object_path(
        KREGIONS_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_kregions(running=False) -> None:
    if running:
        return
    cmd = "result = Kernel.enumerateRanges('---');"
    util.run_script("list_ranges", cmd, put_kregions_callback)


def ghidra_trace_put_kregions() -> None:
    """
    Read the memory map, if applicable, and write to the trace's kernel Regions
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_kregions()


def put_heap_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    pid = util.selected_process()
    if pid is None:
        return
    sid = util.selected_session()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for r in values:
        # print(f"R={r}")
        base = r['base']
        size = r['size']
        rpath = HEAP_REGION_PATTERN.format(sid=sid, start=base)
        robj = trace.create_object(rpath)
        keys.append(HEAP_REGION_KEY_PATTERN.format(start=base))

        base_base, base_addr = mapper.map(pid, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        robj.set_value('Range', base_addr.extend(size))
        robj.set_value('_display', '{}:{:x}'.format(base, size))
        robj.insert()
    trace.proxy_object_path(
        HEAP_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_heap(running=False) -> None:
    if running:
        return
    cmd = "result = Process.enumerateMallocRanges('---');"
    util.run_script("list_heap_ranges", cmd, put_heap_callback)


def ghidra_trace_put_heap() -> None:
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_heap()


def put_modules_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for m in values:
        # print(f"M={m}")
        name = m['name']
        path = m['path']
        base = m['base']
        size = m['size']
        util.put_module_address(path, base)
        mpath = MODULE_PATTERN.format(sid=sid, pid=pid, modpath=path)
        mobj = trace.create_object(mpath)
        keys.append(MODULE_KEY_PATTERN.format(modpath=path))

        base_base, base_addr = mapper.map(pid, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        mobj.set_value('Range', base_addr.extend(size))
        mobj.set_value('Name', name)
        mobj.set_value('Path', path)
        util.current_state[path] = base
        util.current_state[base] = size
        mobj.set_value('_display', '{}:{:x} {} '.format(base, size, name))
        mobj.insert()
        trace.create_object(mpath+".Sections").insert()
        trace.create_object(mpath+".Exports").insert()
        trace.create_object(mpath+".Imports").insert()
        trace.create_object(mpath+".Symbols").insert()
        trace.create_object(mpath+".Dependencies").insert()
    trace.proxy_object_path(
        MODULES_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_modules(running=False) -> None:
    if running:
        return
    cmd = "result = Process.enumerateModules();"
    util.run_script("list_modules", cmd, put_modules_callback)


def ghidra_trace_put_modules() -> None:
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_modules()


def put_kmodules_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for m in values:
        # print(f"M={m}")
        name = m['name']
        base = m['base']
        size = m['size']
        mpath = KMODULE_PATTERN.format(sid=sid, modpath=name)
        mobj = trace.create_object(mpath)
        keys.append(KMODULE_KEY_PATTERN.format(modpath=name))

        base_base, base_addr = mapper.map(0, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        mobj.set_value('Range', base_addr.extend(size))
        mobj.set_value('Name', name)
        util.current_state[base] = size
        mobj.set_value('_display', '{}:{:x} {} '.format(base, size, name))
        mobj.insert()
    trace.proxy_object_path(
        KMODULES_PATTERN.format(sid=sid)).retain_values(keys)


def put_kmodules(running=False) -> None:
    if running:
        return
    cmd = "result = Kernel.enumerateModules();"
    util.run_script("list_kmodules", cmd, put_kmodules_callback)


def ghidra_trace_put_kmodules() -> None:
    """
    Gather object files, if applicable, and write to the trace's KModules
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_kmodules()


def put_sections_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)
    cbdata = get_data_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for r in values:
        # print(f"R={r}")
        base = r['base']
        size = r['size']
        prot = r['protection']
        rpath = SECTION_PATTERN.format(
            sid=sid, pid=pid, modpath=cbdata, start=base)
        robj = trace.create_object(rpath)
        keys.append(SECTION_KEY_PATTERN.format(start=base))

        base_base, base_addr = mapper.map(pid, int(base, 0))
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        robj.set_value('Range', base_addr.extend(size))
        util.current_state[base] = size
        robj.set_value('Protection', prot)
        if 'file' in r.keys():
            file = r['file']
            fpath = file['path']
            foffset = file['offset']
            fsize = file['size']
            robj.set_value('File', '{} {:x}:{:x}'.format(
                fpath, foffset, fsize))
        robj.set_value('_display', '{}:{:x} {} '.format(base, size, prot))
        robj.insert()
    trace.proxy_object_path(
        SECTIONS_PATTERN.format(sid=sid, pid=pid, modpath=cbdata)).retain_values(keys)


def put_sections(modpath, addr, running=False) -> None:
    if running:
        return
    sid = util.selected_session()
    pid = util.selected_process()

    cmd = "result = Process.findModuleByAddress('" + \
        addr+"').enumerateRanges('---');"
    util.run_script_with_data("list_sections", cmd,
                              modpath, put_sections_callback)


def ghidra_trace_put_sections(modpath, addr) -> None:
    """
    Gather object files, if applicable, and write to the trace's module Sections
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_sections(modpath, addr)


def put_imports_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)
    cbdata = get_data_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for i in values:
        # print(f"I={i}")
        name = i['name']
        addr = i['address']
        type = i['type']
        ipath = IMPORT_PATTERN.format(
            sid=sid, pid=pid, modpath=cbdata, addr=addr)
        iobj = trace.create_object(ipath)
        keys.append(IMPORT_KEY_PATTERN.format(addr=addr))

        iobj.set_value('Name', name)
        iobj.set_value('Address', addr)
        util.current_state[addr] = name
        iobj.set_value('Type', type)
        if 'module' in i.keys():
            iobj.set_value('Module', i['module'])
        if 'slot' in i.keys():
            iobj.set_value('Slot', i['slot'])
        iobj.set_value('_display', '{} {} '.format(addr, name))
        iobj.insert()
    trace.proxy_object_path(
        IMPORTS_PATTERN.format(sid=sid, pid=pid, modpath=cbdata)).retain_values(keys)


def put_imports(modpath, addr, running=False) -> None:
    if running:
        return
    cmd = "result = Process.findModuleByAddress('" + \
        addr+"').enumerateImports();"
    util.run_script_with_data(
        "list_imports", cmd, modpath, put_imports_callback)


def ghidra_trace_put_imports(modpath, addr) -> None:
    """
    Gather object files, if applicable, and write to the trace's module Imports
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_imports(modpath, addr)


def put_exports_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)
    cbdata = get_data_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for x in values:
        # print(f"X={x}")
        name = x['name']
        addr = x['address']
        type = x['type']
        xpath = EXPORT_PATTERN.format(
            sid=sid, pid=pid, modpath=cbdata, addr=addr)
        xobj = trace.create_object(xpath)
        keys.append(EXPORT_KEY_PATTERN.format(addr=addr))

        xobj.set_value('Name', name)
        xobj.set_value('Address', addr)
        util.current_state[addr] = name
        xobj.set_value('Type', type)
        if 'module' in x.keys():
            xobj.set_value('Module', x['module'])
        xobj.set_value('_display', '{} {} '.format(addr, name))
        xobj.insert()
    trace.proxy_object_path(
        EXPORTS_PATTERN.format(sid=sid, pid=pid, modpath=cbdata)).retain_values(keys)


def put_exports(modpath, addr, running=False) -> None:
    if running:
        return
    cmd = "result = Process.findModuleByAddress('" + \
        addr+"').enumerateExports();"
    util.run_script_with_data(
        "list_imports", cmd, modpath, put_exports_callback)


def ghidra_trace_put_exports(modpath, addr) -> None:
    """
    Gather object files, if applicable, and write to the trace's module exports
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_exports(modpath, addr)


def put_symbols_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)
    cbdata = get_data_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for sym in values:
        # print(f"S={sym}")
        name = sym['name']
        addr = sym['address']
        type = sym['type']
        size = sym['size']
        isglobal = sym['isGlobal']
        spath = SYMBOL_PATTERN.format(
            sid=sid, pid=pid, modpath=cbdata, addr=addr)
        sobj = trace.create_object(spath)
        keys.append(SYMBOL_KEY_PATTERN.format(addr=addr))

        sobj.set_value('Name', name)
        sobj.set_value('Address', addr)
        util.current_state[addr] = name
        sobj.set_value('Type', type)
        sobj.set_value('Size', size)
        sobj.set_value('IsGlobal', isglobal)
        if 'section' in sym.keys():
            section = sym['section']
            id = section['id']
            sobj.set_value('Section', id)
        sobj.set_value('_display', '{} {} '.format(addr, name))
        sobj.insert()
    trace.proxy_object_path(
        SYMBOLS_PATTERN.format(sid=sid, pid=pid, modpath=cbdata)).retain_values(keys)


def put_symbols(modpath, addr, running=False) -> None:
    if running:
        return
    cmd = "result = Process.findModuleByAddress('" + \
        addr+"').enumerateSymbols();"
    util.run_script_with_data(
        "list_symbols", cmd, modpath, put_symbols_callback)


def ghidra_trace_put_symbols(modpath, addr) -> None:
    """
    Gather object files, if applicable, and write to the trace's module symbols
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_symbols(modpath, addr)


def put_dependencies_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)
    cbdata = get_data_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for dep in values:
        # print(f"S={sym}")
        name = dep['name']
        type = dep['type']
        dpath = DEPENDENCY_PATTERN.format(
            sid=sid, pid=pid, modpath=cbdata, name=name)
        dobj = trace.create_object(dpath)
        keys.append(DEPENDENCY_KEY_PATTERN.format(name=name))

        dobj.set_value('Name', name)
        dobj.set_value('Type', type)
        dobj.set_value('_display', '{} '.format(name))
        dobj.insert()
    trace.proxy_object_path(
        DEPENDENCIES_PATTERN.format(sid=sid, pid=pid, modpath=cbdata)).retain_values(keys)


def put_dependencies(modpath, addr, running=False) -> None:
    if running:
        return
    cmd = "result = Process.findModuleByAddress('" + \
        addr+"').enumerateDependencies();"
    util.run_script_with_data("list_dependencies", cmd,
                              modpath, put_dependencies_callback)


def ghidra_trace_put_dependencies(modpath, addr) -> None:
    """
    Gather object files, if applicable, and write to the trace's module symbols
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_dependencies(modpath, addr)


def convert_state(t) -> str:
    if t.IsSuspended():
        return 'SUSPENDED'
    if t.IsStopped():
        return 'STOPPED'
    return 'RUNNING'


def get_values_from_callback(message: Dict[str, Any], data: Any):
    if message is None:
        return {}
    if message['type'] == 'error':
        print(f"{message['description']}")
        return {}
    if 'payload' not in message.keys():
        return {}
    payload = message['payload']
    json_dict = json.loads(payload)
    # print(f"{json_dict}")
    return json_dict['value']


def get_data_from_callback(message: Dict[str, Any], data: Any):
    if message is None or 'payload' not in message.keys():
        return {}
    payload = message['payload']
    json_dict = json.loads(payload)
    # print(f"{json_dict}")
    return json_dict['data']


def put_event_thread(tid=None) -> None:
    pid = util.selected_process()
    # Assumption: Event thread is selected by pydbg upon stopping
    trace = STATE.require_trace()
    if tid is None:
        tid = util.selected_thread()
    if tid != None:
        tpath = THREAD_PATTERN.format(pid=pid, tid=tid)
        tobj = trace.proxy_object_path(tpath)
    else:
        tobj = None
    trace.proxy_object_path('').set_value('_event_thread', tobj)


def compute_thread_display(i, pid, tid, t) -> str:
    display = '{:d} {:x}:{:x}'.format(i, pid, tid)
    if t['name'] is not None:
        display += " " + t['name']
    if t['state'] is not None:
        display += " " + t['state']
    return display


def put_threads_callback(message: Dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    trace = STATE.require_trace()
    sid = util.selected_session()
    pid = util.selected_process()
    keys = []
    i = 0
    for t in values:
        # print(f"T={t}")
        tid = t['id']
        util.select_thread(tid)
        name = t['name']
        state = t['state']
        context = t['context']
        tpath = THREAD_PATTERN.format(sid=sid, pid=pid, tid=tid)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tid=tid))

        tobj.set_value('TID', tid)
        tobj.set_value('Name', name)
        tobj.set_value('_short_display',
                       '{:x} {:x}:{:x}'.format(i, pid, tid))
        tobj.set_value('_display', compute_thread_display(i, pid, tid, t))
        istate = compute_proc_state(tid)
        tobj.set_value('State', istate)
        tobj.insert()
        i += 1

        space = REGS_PATTERN.format(sid=sid, pid=pid, tid=tid)
        trace.create_overlay_space('register', space)
        regs = trace.create_object(space)
        regs.insert()
        mapper = trace.extra.require_rm()
        values = []
        for r in context.keys():
            rval = context[r]
            regs.set_value(r, rval)
            try:
                values.append(mapper.map_value(pid, r, int(rval, 0)))
            except Exception:
                pass
        trace.put_registers(space, values)
        trace.create_object(tpath+".Stack").insert()

    trace.proxy_object_path(
        THREADS_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_threads(running=False) -> None:
    if running:
        return
    cmd = "result = Process.enumerateThreads();"
    util.run_script("list_threads", cmd, put_threads_callback)


def ghidra_trace_put_threads() -> None:
    """
    Put the current process's threads into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_threads()


def compute_frame_display(i, f) -> str:
    display = '#{:d} {}'.format(i, f['address'])
    if f['name'] is not None:
        display += " " + f['name']
    if f['moduleName'] is not None:
        display += " " + f['moduleName']
    if f['fileName'] is not None:
        display += " " + f['fileName']
    if f['lineNumber'] is not None:
        display += " " + str(f['lineNumber'])
    if f['column'] is not None:
        display += " " + str(f['column'])
    return display


def put_frames_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    if pid is None:
        return
    tid = util.selected_thread()
    keys = []
    level = 0
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    for f in values:
        # print(f"F={f}")
        addr = f['address']
        name = f['name']
        module = f['moduleName']
        file = f['fileName']
        lineno = f['lineNumber']
        col = f['column']
        fpath = FRAME_PATTERN.format(
            sid=sid, pid=pid, tid=tid, level=level)
        fobj = trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=level))

        base, pc = mapper.map(pid, int(addr, 0))
        if base != pc.space:
            trace.create_overlay_space(base, pc.space)
        fobj.set_value('PC', pc)
        if name is not None:
            fobj.set_value('Name', name)
        if module is not None:
            fobj.set_value('Function', module)
            fobj.set_value('Module', module)
        if file is not None:
            fobj.set_value('File', file)
        if lineno is not None:
            fobj.set_value('Line #', lineno)
        if col is not None:
            fobj.set_value('Column #', col)
        fobj.set_value('_display', compute_frame_display(level, f))
        fobj.insert()
        level += 1
    trace.proxy_object_path(
        FRAMES_PATTERN.format(sid=sid, pid=pid, tid=tid)).retain_values(keys)


def put_frames() -> None:
    cmd = "result = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);"
    util.run_script("list_frames", cmd, put_frames_callback)


def ghidra_trace_put_frames() -> None:
    """
    Put the current thread's frames into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_frames()


def map_address(address):
    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    base, addr = mapper.map(pid, address)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    return (base, addr)


def put_loaded_classes_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for c in values:
        # print(f"M={m}")
        key = None
        name = ""
        if 'name' in c.keys():
            name = c['name']
            key = name
        path = ""
        if 'path' in c.keys():
            path = c['path']
            key = path
        cpath = CLASS_PATTERN.format(sid=sid, pid=pid, path=key)
        cobj = trace.create_object(cpath)
        keys.append(CLASS_KEY_PATTERN.format(path=key))

        cobj.set_value('Name', name)
        cobj.set_value('Path', path)
        cobj.set_value('_display', '{}'.format(path))
        cobj.insert()

        mkeys = []
        if 'methods' in c.keys():
            methods = c['methods']
            for m in methods:
                mpath = METHOD_PATTERN.format(
                    sid=sid, pid=pid, path=key, name=m)
                mobj = trace.create_object(mpath)
                keys.append(METHOD_KEY_PATTERN.format(name=m))
                mobj.insert()
            trace.proxy_object_path(
                METHODS_PATTERN.format(sid=sid, pid=pid, path=key)).retain_values(mkeys)

    trace.proxy_object_path(
        CLASSES_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_loaded_classes_objc(running=False) -> None:
    if running:
        return
    cmd = "result = ObjC.enumerateLoadedClassesSync();"
    util.run_script("list_loaded_classes", cmd, put_loaded_classes_callback)


# TODO: UNTESTED
def ghidra_trace_put_loaded_classes_objc() -> None:
    """
    Gather object files, if applicable, and write to the trace's Classes
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_loaded_classes_objc()


def put_loaded_classes_java(running=False) -> None:
    if running:
        return
    cmd = "result = Java.enumerateLoadedClassesSync();"
    util.run_script("list_loaded_classes", cmd, put_loaded_classes_callback)


# TODO: UNTESTED
def ghidra_trace_put_loaded_classes_java() -> None:
    """
    Gather object files, if applicable, and write to the trace's Classes
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_loaded_classes_java()


def put_class_loaders_callback(message: dict[str, Any], data: Any) -> None:
    values = get_values_from_callback(message, data)

    sid = util.selected_session()
    pid = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for l in values:
        # print(f"M={m}")
        lpath = LOADER_PATTERN.format(sid=sid, pid=pid, path=l)
        lobj = trace.create_object(lpath)
        keys.append(LOADER_KEY_PATTERN.format(path=l))
        lobj.insert()
    trace.proxy_object_path(
        LOADERS_PATTERN.format(sid=sid, pid=pid)).retain_values(keys)


def put_class_loaders_java(running=False) -> None:
    if running:
        return
    cmd = "result = Java.enumerateClassLoadersSync();"
    util.run_script("list_loaded_classes", cmd, put_class_loaders_callback)


# TODO: UNTESTED
def ghidra_trace_put_class_loaders_java() -> None:
    """
    Gather object files, if applicable, and write to the trace's ClassLoaders
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_class_loaders_java()


def ghidra_trace_put_all() -> None:
    """
    Put everything currently selected into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_sessions()
        put_session_attributes()
        put_environment()
        put_available()
        put_applications()
        put_processes()
        put_regions()
        put_modules()
        put_threads()
        put_frames()


def ghidra_trace_install_hooks() -> None:
    """
    Install hooks to trace in Ghidra
    """

    # hooks.install_hooks()


def ghidra_trace_remove_hooks() -> None:
    """
    Remove hooks to trace in Ghidra

    Using this directly is not recommended, unless it seems the hooks are
    preventing pydbg or other extensions from operating. Removing hooks will break
    trace synchronization until they are replaced.
    """

    # hooks.remove_hooks()


def get_prompt_text() -> str:
    try:
        return 'Frida>'
    except util.DebuggeeRunningException:
        return 'Running>'


def exec_cmd(cmd) -> None:
    util.run_script_no_ret("", cmd, util.on_message_print)


def repl() -> None:
    print("")
    print("This is the Frida Javascript REPL. To drop to Python, type .exit")
    while True:
        print(get_prompt_text(), end=' ')
        try:
            cmd = input().strip()
            if cmd == '':
                continue
            elif cmd == '.exit':
                break
            exec_cmd(cmd)
        except KeyboardInterrupt as e:
            break
        except BaseException as e:
            pass  # Error is printed by another mechanism
    print("")
    print("You have left the Frida Javascript REPL and are now at the Python "
          "interpreter.")
    print("To re-enter, type repl()")
