Once Volatility and the extension have been installed:

- run gdb (run qemu -s with your target)
- target remote :1234
- maintenance packet Qqemu.PhyMemMode:1 (once and/or before any "ghidra trace" operations
- python import ghidravol (which loads ghidragdb and the Volatility extensions)
- ghidra trace listen
- run the "ConnectTraceRmiScript" from ghidra (enter "localhost" & the port from the previous step)
- ghidra trace vol-start (to create the trace)
- ghidra trace tx-start "tx" (to initiate a transaction)
- ghidra trace put-all (to populate ghidragdb artifacts)
- ghidra trace put-all-vol-xxx (xxx=win/mac/linux)
- any other commands you might want
- ghidra trace tx-commit
- ghidra trace activate 

Subsequent pushes require transactions but not activation.
Activation with an existing trace open in Ghidra will fail.
