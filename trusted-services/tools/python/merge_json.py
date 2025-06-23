#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) 2022, Arm Limited. All rights reserved.

"""
Merge multiple json files in the order of the command line arguments.
"""

import argparse
import json
import os

def update_relative_path(path, original_json_path, merged_json_path):
    """
    Update relative path according to its original and new base directory.
    """
    original_base_dir = os.path.dirname(original_json_path)
    merged_base_dir = os.path.dirname(merged_json_path)

    return os.path.relpath(original_base_dir + "/" + path, merged_base_dir)

parser = argparse.ArgumentParser(
    prog="merge_json",
    description="Merge multiple JSON files into a single file.",
    epilog="The merge happens in the order of command line arguments.")
parser.add_argument("output", help="Output JSON file")
parser.add_argument("inputs", nargs="+", help="Input JSON files")

args = parser.parse_args()

json_combined = {}

for input_json_path in args.inputs:
    print(f"Adding {input_json_path}")
    with open(input_json_path, "rt", encoding="ascii") as f:
        json_fragment = json.load(f)

        # Align relative paths to merged JSON file's path
        # The original JSON fragment and the merged JSON file might be placed
        # in a different directory. This requires updating the relative paths
        # in the JSON, so the merged file can have paths relative to itself.
        keys = list(json_fragment.keys())
        assert keys
        sp = keys[0]

        json_fragment[sp]["image"] = update_relative_path(
            json_fragment[sp]["image"], input_json_path, args.output)
        json_fragment[sp]["pm"] = update_relative_path(
            json_fragment[sp]["pm"], input_json_path, args.output)

        json_combined = {**json_combined, **json_fragment}

with open(args.output, "wt", encoding="ascii") as f:
    json.dump(json_combined, f, indent=4)
