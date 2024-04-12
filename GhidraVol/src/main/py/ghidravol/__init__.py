## ###
#  IP: Volatility License
##
def try_gdb():
    try:
        import gdb
        return True
    except:
        return False


IS_GDB = try_gdb()

if IS_GDB:
    from ghidragdb import util, commands
    import ghidravol.gdb_volpatch as volpatch
    import ghidravol.gdb_vol as vol
else:
    from ghidralldb import util, commands
    import ghidravol.lldb_volpatch as volpatch
    import ghidravol.lldb_vol as vol


from . import commands_linux, commands_macos, commands_windows
from . import volcmd, tslist

DebuggerLayer = None

if IS_GDB:
    from . import gdb_commands
    DebuggerLayer = volpatch.GdbLayer
else:
    from . import lldb_commands
    DebuggerLayer = volpatch.LldbLayer
