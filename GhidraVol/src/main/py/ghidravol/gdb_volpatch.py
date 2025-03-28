## ###
#  IP: Volatility License
##
import gdb
from ghidravol import util


from typing import Any, Dict, IO, List, Optional, Union


from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical, intel, resources


def UrlLayer(
    context: interfaces.context.ContextInterface,
    config_path: str,
    name: str,
    metadata: Optional[Dict[str, Any]] = None
) -> interfaces.layers.DataLayerInterface:
    #print(f"Config: {context.config}")
    if context.config.get('plugins.stack.FileLayer.location') is not None:
        location = context.config['plugins.stack.FileLayer.location']
        if location.startswith("vol:"):
            return GdbLayer(context, config_path, name, metadata)
    return FileLayer(context, config_path, name, metadata)


class GdbLayer(interfaces.layers.DataLayerInterface):
    """A DataLayer class backed by the memory of the current target in GDB."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None
        # TODO: Keep handle for a specific process?
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return []

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        # TODO: Can we get a good answer from gdb?
        # Perhaps using the memory map, but for qemu, not sure what we get
        return 2**64 - 1

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        try:
            gdb.selected_inferior().read_memory(offset, length)
            return True
        except gdb.MemoryError:
            return False

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""
        #print(f"READ {hex(offset)}:{hex(length)}")
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name, invalid_address, "Offset outside of the buffer boundaries"
            )

        try:
            inf = gdb.selected_inferior()
            if offset == 0xdbace000:
                frame = gdb.selected_frame()
                if frame is not None:
                    offset = frame.read_register("cr3")
            return bytes(inf.read_memory(offset, length))
        except Exception as e:
            print(f"Error reading {offset}:{length} : {e}")

    def write(self, offset: int, data: bytes) -> None:
        gdb.selected_inferior().write_memory(offset, data)


FileLayer = physical.FileLayer
physical.FileLayer = UrlLayer
