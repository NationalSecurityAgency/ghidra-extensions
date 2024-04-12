## ###
#  IP: Volatility License
##
import argparse
import inspect
import datetime
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import traceback

from functools import wraps
from typing import Any, Callable, Dict, Type, Union, List, Tuple
from urllib import parse, request

import volatility3.plugins
import volatility3.symbols
from volatility3 import framework
from volatility3.cli import text_renderer, volargparse
from volatility3.cli.text_renderer import display_disassembly, hex_bytes_as_text, optional, quoted_optional, multitypedata_as_text
from volatility3.framework import automagic, configuration, constants, contexts, exceptions, interfaces, plugins, renderers
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

volatility3.framework.require_interface_version(2, 0, 0)
volatility3.plugins.__path__ = constants.PLUGINS_PATH
failures = framework.import_files(volatility3.plugins, True)

print(sys.version)

#vol_mnt = os.environ.get("VOL_MNT", "file://////Users//dbm//vmware//Win10x64.vmwarevm//Win10x64-Snapshot2.vmem")
vol_mnt = os.environ.get("VOL_MNT", "vol:////")
parent = os.path.dirname(inspect.getfile(inspect.currentframe()))
vol_cfg = os.environ.get("VOL_CFG", parent+"/config/")


class PrintedProgress(object):
    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        message = f"\rProgress: {round(progress, 2): 7.2f}\t\t{description or ''}"
        message_len = len(message)
        self._max_message_len = max([self._max_message_len, message_len])
        print(message, end=(" " * (self._max_message_len - message_len)) + "\r")


def vol(cmd_args):
    progress_callback = PrintedProgress()
    plugin_list = framework.list_plugins()
    plugin = plugin_list[cmd_args[0]]

    # Do the initialization
    ctx = contexts.Context()
    failures = framework.import_files(
        volatility3.plugins, True
    )
    automagics = automagic.available(ctx)

    base_config_path = "plugins"
    plugin_config_path = interfaces.configuration.path_join(
        base_config_path, plugin.__name__
    )

    try:
        single_location = requirements.URIRequirement.location_from_file(
            vol_mnt
        )
        ctx.config["automagic.LayerStacker.single_location"] = single_location
    except ValueError as excp:
        print(str(excp))

    config = cmd_args[0]
    config = config.split('.')[0]
    path = vol_cfg + config + ".config"

    with open(path, "r") as f:
        json_val = json.load(f)
        ctx.config.splice(
            plugin_config_path,
            interfaces.configuration.HierarchicalDict(json_val),
        )

    # It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
    automagics = automagic.choose_automagic(automagics, plugin)

    if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
        ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
            plugin
        )

    constructed = None
    try:
        progress_callback = PrintedProgress()

        constructed = plugins.construct_plugin(
            ctx,
            automagics,
            plugin,
            base_config_path,
            progress_callback,
            None
        )
    except exceptions.UnsatisfiedException as excp:
        print(excp)

    # renderers = dict(
    #    [
    #        (x.name.lower(), x)
    #        for x in framework.class_subclasses(text_renderer.CLIRenderer)
    #    ]
    # )

    try:
        if constructed:
            ret = constructed.run()
            # renderers["json"]().render(ret)
            return render(ret)
    except exceptions.VolatilityException as excp:
        print(excp)


def render(grid: interfaces.renderers.TreeGrid):
    final_output: Tuple[
        Dict[str, List[interfaces.renderers.TreeNode]],
        List[interfaces.renderers.TreeNode],
    ] = ({}, [])

    _type_renderers = {
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: lambda x: x.isoformat()
        if not isinstance(x, interfaces.renderers.BaseAbsentValue)
        else None,
        "default": lambda x: x,
    }

    def visitor(
        node: interfaces.renderers.TreeNode,
        accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
    ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
        # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
        acc_map, final_tree = accumulator
        node_dict: Dict[str, Any] = {"__children": []}
        for column_index in range(len(grid.columns)):
            column = grid.columns[column_index]
            renderer = _type_renderers.get(
                column.type, _type_renderers["default"]
            )
            data = renderer(list(node.values)[column_index])
            if isinstance(data, interfaces.renderers.BaseAbsentValue):
                data = None
            node_dict[column.name] = data
        if node.parent:
            acc_map[node.parent.path]["__children"].append(node_dict)
        else:
            final_tree.append(node_dict)
        acc_map[node.path] = node_dict

        return (acc_map, final_tree)

    if not grid.populated:
        grid.populate(visitor, final_output)
    else:
        grid.visit(node=None, function=visitor,
                   initial_accumulator=final_output)

    return final_output[1]
