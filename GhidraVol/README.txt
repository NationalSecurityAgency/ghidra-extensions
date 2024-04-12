Once Volatility and the extension have been installed, run either the gdb-vol or lldb-vol shells.

To manually populate the Volatility node:
- ghidra trace tx-start "tx" (to initiate a transaction)
- ghidra trace put-all-vol
- any other commands you might want
- ghidra trace tx-commit

Enabling thread lists for windows requires copying the tslist.py file to the volatility3/framework/plugins/windows directory.

