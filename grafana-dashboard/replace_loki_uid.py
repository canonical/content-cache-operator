# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Replace the uid for all loki datasources in the grafana JSON model file.

For help run `python -m replace_loki_uid -h`.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path

@dataclass
class Arguments:
    """The arguments of the CLI."""
    input_file: Path
    output_file: Path
    
    
def replace_loki_uid(data):
    """Recursively check and replace the uid for loki data sources."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "datasource":
                if "type" in value and value["type"] == "loki" and "uid" in value:
                    value["uid"] = "${lokids}"
            replace_loki_uid(value)
    
    if isinstance(data, list):
        for value in data:
            replace_loki_uid(value)


def parse_args(): 
    """Parse the CLI arguments."""
    parser = argparse.ArgumentParser(description="Replace the uid for all loki datasources in the grafana JSON model file.")
    parser.add_argument("-i", "--input", required=True, help="The input file to transform.")
    parser.add_argument("-o", "--output", required=True, help="The output file after transform.")
    args = parser.parse_args()
    return Arguments(Path(args.input), Path(args.output))


def main():
    """Execute the CLI for replacing the UID of loki data source of grafana JSON model."""
    args = parse_args()
    
    with open(args.input_file) as file:
        data = json.load(file)
        replace_loki_uid(data)
    
    with open(args.output_file, mode="w") as file:
        json.dump(data, file)

if __name__ == "__main__":
    main()
