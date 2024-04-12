## ###
#  IP: Volatility License
##
import datetime
import logging
from typing import Callable, Iterable, List, Type

from volatility3.framework import renderers, interfaces, layers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class TsList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the processes present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)
    PHYSICAL_DEFAULT = False

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.BooleanRequirement(name='physical',
                                            description='Display physical offsets instead of virtual',
                                            default=cls.PHYSICAL_DEFAULT,
                                            optional=True),
            requirements.ListRequirement(name='pid',
                                         element_type=int,
                                         description="Process ID to include (all other processes are excluded)",
                                         optional=True),
            requirements.BooleanRequirement(name='dump',
                                            description="Extract listed processes",
                                            default=False,
                                            optional=True)
        ]

    @classmethod
    def process_dump(
            cls, context: interfaces.context.ContextInterface, kernel_table_name: str, pe_table_name: str,
            proc: interfaces.objects.ObjectInterface,
            open_method: Type[interfaces.plugins.FileHandlerInterface]) -> interfaces.plugins.FileHandlerInterface:
        """Extracts the complete data for a process as a FileHandlerInterface

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            pe_table_name: the name for the symbol table containing the PE format symbols
            proc: the process object whose memory should be output
            open_method: class to provide context manager for opening the file

        Returns:
            An open FileHandlerInterface object containing the complete data for the process or None in the case of failure
        """

        file_handle = None
        try:
            proc_layer_name = proc.add_process_layer()
            peb = context.object(kernel_table_name + constants.BANG + "_PEB",
                                 layer_name=proc_layer_name,
                                 offset=proc.Peb)

            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset=peb.ImageBaseAddress,
                                        layer_name=proc_layer_name)
            file_handle = open_method(
                f"pid.{proc.UniqueProcessId}.{peb.ImageBaseAddress:#x}.dmp")
            for offset, data in dos_header.reconstruct():
                file_handle.seek(offset)
                file_handle.write(data)
        except Exception as excp:
            vollog.debug(
                f"Unable to dump PE with pid {proc.UniqueProcessId}: {excp}")

        return file_handle

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None, exclude: bool = False) -> Callable[
            [interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process IDs.

        Args:
            pid_list: A list of process IDs that are acceptable, all other processes will be filtered out
            exclude: Accept only tasks that are not in pid_list

        Returns:
            Filter function for passing to the `list_processes` method
        """
        def filter_func(_): return False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            if exclude:
                def filter_func(x): return x.UniqueProcessId in filter_list
            else:
                def filter_func(x): return x.UniqueProcessId not in filter_list
        return filter_func

    @classmethod
    def create_name_filter(cls, name_list: List[str] = None, exclude: bool = False) -> Callable[
            [interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process names.

        Args:
            name_list: A list of process names that are acceptable, all other processes will be filtered out
            exclude: Accept only tasks that are not in name_list
        Returns:
            Filter function for passing to the `list_processes` method
        """
        def filter_func(_): return False
        # FIXME: mypy #4973 or #2608
        name_list = name_list or []
        filter_list = [x for x in name_list if x is not None]
        if filter_list:
            if exclude:
                def filter_func(x): return utility.array_to_string(
                    x.ImageFileName) in filter_list
                print("if exclude")
            else:
                def filter_func(x): return utility.array_to_string(
                    x.ImageFileName) not in filter_list
                print("if include?")
        return filter_func

    @classmethod
    def list_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str,
                       filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: False, include_threads: bool = True) -> \
            Iterable[interfaces.objects.ObjectInterface]:
            # include threads here?
        """Lists all the processes in the primary layer that are in the pid
        config option.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            filter_func: A function which takes an EPROCESS object and returns True if the process should be ignored/filtered

        Returns:
            The list of EPROCESS objects from the `layer_name` layer's PsActiveProcessHead list after filtering
        """

        # We only use the object factory to demonstrate how to use one
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(
            symbol_table, layer_name=layer_name, offset=kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address

        # add more swit process to thread here?
        list_entry = ntkrnlmp.object(
            object_type="_LIST_ENTRY", offset=ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt_symbols!_EPROCESS" could have been used, but would rely on the "nt_symbols" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type(
            "_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(
            object_type="_EPROCESS", offset=list_entry.vol.offset - reloff, absolute=True)
    # threads?^

        for proc in eproc.ActiveProcessLinks:
            for thread in proc.ThreadListHead.to_list(f"{symbol_table}{constants.BANG}_ETHREAD", "ThreadListEntry"):
                # yield thread

                if not filter_func(proc):
                    yield thread

        # maybe don't even need the include_threads?
            # if include_threads:
                #print("hit if include threads?")
                # yield from proc.Pcb.ThreadListHead

                # never hits this?^ indentation seems right

    def _generator(self):

        kernel = self.context.modules[self.config['kernel']]

        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types=pe.class_types)

        memory = self.context.layers[kernel.layer_name]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        for thread in self.list_processes(self.context,
                                          kernel.layer_name,
                                          kernel.symbol_table_name,
                                          filter_func=self.create_pid_filter(self.config.get('pid', None)), include_threads=True):
                                         # , ,include_threads: bool = True
                                        # added include threads here

            # if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                #offset = thread.vol.offset
            # else:
                #(_, _, offset, _, _) = list(memory.mapping(offset = thread.vol.offset, length = 0))[0]
            # ^figure out offset later!
            file_output = "Disabled"

            try:
                if self.config['dump']:
                    file_handle = self.process_dump(self.context, kernel.symbol_table_name,
                                                    pe_table_name, thread, self.open)
                    file_output = "Error outputting file"

                    if file_handle:
                        file_handle.close()
                        file_output = str(file_handle.preferred_filename)

                yield (0, (thread.Cid.UniqueProcess, thread.Cid.UniqueThread))
        # All UniqueProcessId... (process changed to threads) in this yield func.
            except exceptions.InvalidAddressException:
                vollog.info(
                    f"Invalid process found at address: {proc.vol.offset:x}. Skipping")

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Process: {row_data[0]} {row_data[2]} ({row_data[3]})"
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def get_next_entry(self, member):
        return self.m(member).dereference()

    def list_of_type(self, type, member, forward=True, head_sentinel=True):
        if not self.is_valid():
            return

        # Get the first element
        if forward:
            nxt = self.get_next_entry("Flink")
        else:
            nxt = self.get_next_entry("Blink")

        offset = self.obj_vm.profile.get_obj_offset(type, member)

        seen = set()
        if head_sentinel:
            # We're a header element and not to be included in the list
            seen.add(self.obj_offset)

        while nxt.is_valid() and nxt.obj_offset not in seen:

            # Instantiate the object
            item = obj.Object(type, offset=nxt.obj_offset - offset,
                              vm=self.obj_vm,
                              parent=self.obj_parent,
                              native_vm=self.obj_native_vm,
                              name=type)

            seen.add(nxt.obj_offset)

            yield item

            if forward:
                nxt = item.m(member).get_next_entry("Flink")
            else:
                nxt = item.m(member).get_next_entry("Blink")

    def __nonzero__(self):
        # List entries are valid when both Flinks and Blink are valid
        return bool(self.Flink) or bool(self.Blink)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)

    def run(self):
        offsettype = "(V)" if not self.config.get(
            'physical', self.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid([("PID", int), ("TID", int)], self._generator())
        # ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime), ("State", str)], self._generator())
