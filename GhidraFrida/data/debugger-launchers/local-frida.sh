#!/usr/bin/bash
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
#@title frida
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>frida</tt></h3>
#@desc   <p>This will launch the target on the local machine using <tt>frida</tt>. 
#@desc   Frida must already be embedded in the Python 3 interpreter. You will also
#@desc   need <tt>protobuf</tt> and <tt>psutil</tt> installed for Python 3.</p>
#@desc </body></html>
#@menu-group local
#@icon icon.debugger
#@help TraceRmiLauncherServicePlugin#frida
#@env OPT_PYTHON_PATH:str="python3" "Path to python" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
# Use env instead of args, because "all args except first" is terrible to implement in batch
#@env OPT_TARGET_DEVICE:str="local" "Device" "The target device"
#@env OPT_TARGET_IMG:str="" "Image" "The target binary executable image"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"

"$OPT_PYTHON_PATH" -i ../support/local-frida.py
