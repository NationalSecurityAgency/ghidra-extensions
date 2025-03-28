#!/usr/bin/env bash
## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
#@title gdb + vol
#@desc <html><body width="300px">
#@desc   <h3>Connect Volatility 3 to <tt>QEMU</tt> or <tt>VMware</tt>.</h3>
#@desc   Connect to a system emulator's <tt>gdb stub</tt> using <tt>GDB</tt> and examine its state
#@desc   using Volatility 3. GDB must already be installed on your system, it must support your target
#@desc    architecture, and it must embed the Python 3 interpreter. You will also need <tt>protobuf</tt>
#@desc    and <tt>volatility3</tt> installed for Python 3.
#@desc </body></html>
#@menu-group vm
#@icon icon.debugger
#@help DebuggerVol3Connector#launcher
#@env TARGET_PORT:int=1234 "Target Port" "Port for connection to gdbstub"
#@env TARGET_OSABI:str="Windows" "Target OS" "OS ABI for target"
#@env OPT_GDB_PATH:file="gdb-multiarch" "Path to gdb" "The path to gdb. Omit the full path to resolve using the system PATH."

if [ -d ${GHIDRA_HOME}/ghidra/.git ]
then
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/ghidra/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/ghidra.ext-u/Ghidra/Extensions/Debugger-agent-volatility/build/pypkg/src:$PYTHONPATH
elif [ -d ${GHIDRA_HOME}/.git ]
then 
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-volatility/build/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src:$PYTHONPATH
else
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-gdb/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-agent-volatility/pypkg/src:$PYTHONPATH
  export PYTHONPATH=$GHIDRA_HOME/Ghidra/Debug/Debugger-rmi-trace/pypkg/src:$PYTHONPATH
fi

"$OPT_GDB_PATH" \
  -q \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "show version" \
  -ex "python import ghidragdb" \
  -ex "python import ghidravol" \
  -ex "target remote localhost:$TARGET_PORT" \
  -ex "set osabi $TARGET_OSABI" \
  -ex "ghidra trace connect \"$GHIDRA_TRACE_RMI_ADDR\"" \
  -ex "ghidra trace start" \
  -ex "ghidra trace sync-enable" \
  -ex "ghidra trace tx-start 'tx'" \
  -ex "ghidra trace put-all" \
  -ex "ghidra trace tx-start 'tx'" \
  -ex "ghidra trace put-all-vol" \
  -ex "ghidra trace tx-commit" 
  -ex "set confirm on" \
  -ex "set pagination on"
