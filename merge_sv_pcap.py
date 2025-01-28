#!/usr/bin/env python

#
# Copyright (C) 2023-2025 Savoir-faire Linux, Inc.
# © 2023 GE Vernova and/or its affiliates. All rights reserved.
# This program is distributed under the Apache 2 license.

import sys
import os
import shutil
import argparse
import subprocess


def arg_parser():
    parser = argparse.ArgumentParser(
        prog="merge_sv_pcap.py",
        description="Concatenate and repeat IEC61850 Sample Values pcap files",
    )

    parser.add_argument(
        "pcap_files",
        nargs="+",
        help="A list of pcap files, can be set multiple times",
    )

    parser.add_argument(
        "-o", "--output", required=True, help="The output pcap file (required)"
    )

    parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=1,
        help="The number of iterations (default: 1)",
    )

    parser.add_argument(
        "-t",
        "--type",
        choices=["pcapng", "pcap"],
        default="pcap",
        help="The output pcap format type (pcapng or pcap, default: pcap)",
    )

    parser.add_argument(
        "-f",
        "--frequency",
        type=int,
        default=60,
        help="The frequency of the current in Hz (default: 60Hz)",
    )

    parser.add_argument(
        "-w",
        "--workdir",
        default=".work",
        help="Temporary working directory (default: .work)",
    )

    args = parser.parse_args()

    print(f"PCAP Files: {args.pcap_files}")
    print(f"Output: {args.output}")
    print(f"Iterations: {args.iterations}")
    print(f"Output Type: {args.type}")
    print(f"Frequency: {args.frequency}Hz")
    print(f"Working Directory: {args.workdir}")

    if args.iterations < 1:
        print("Error: Iterations must be greater than 0", file=sys.stderr)
        sys.exit(1)

    return args


def get_pcap_duration(pcap_file):
    duration = (
        subprocess.check_output(
            f"capinfos -u '{pcap_file}' | grep 'Capture duration' | grep -Eo '[0-9]+[.,]?[0-9]*' | tr ',' '.'",
            shell=True,
        )
        .decode()
        .strip()
    )
    return float(duration)


def shift_pcap_timestamp(pcap_file, shift, output):
    subprocess.run(
        ["editcap", "-t", str(shift), pcap_file, output], check=True
    )


def merge_pcap_files(pcap_files, output, format):
    arg = ["mergecap", "-w", output, "-F", format]
    subprocess.run(arg + pcap_files, check=True)


def merge_and_shift_pcap_files(
    pcap_files,
    output,
    format,
    offset,
    verbose=False,
):
    if len(pcap_files) == 1:
        shutil.copyfile(pcap_files[0], output)
        return

    pcap_to_be_merged = [pcap_files[0]]
    duration = get_pcap_duration(pcap_files[0]) + offset
    nb_files = len(pcap_files)
    if verbose:
        print(f"Shifting [1/{nb_files}]", end="")
    i = 1
    for pcap_file in pcap_files[1:]:
        i += 1
        if verbose:
            print(f"\rShifting [{i}/{nb_files}]", end="", flush=True)
        shift_pcap_timestamp(pcap_file, duration, f"{pcap_file}.shifted")
        pcap_to_be_merged.append(f"{pcap_file}.shifted")
        duration += get_pcap_duration(pcap_file) + offset
    if verbose:
        print(f"\nFinal merge")
    merge_pcap_files(pcap_to_be_merged, output, format)
    for pcap_file in pcap_to_be_merged[1:]:
        os.remove(pcap_file)


def main():
    args = arg_parser()
    pcap_files = args.pcap_files
    output = args.output
    iterations = args.iterations
    pcap_format = args.type
    samples_per_cyle = 80
    frequency = args.frequency
    workdir = args.workdir

    offset = 1 / (frequency * samples_per_cyle)

    if not os.path.exists(workdir):
        os.makedirs(workdir)
    else:
        print(f"Error: {workdir} already exists", file=sys.stderr)
        sys.exit(1)

    # First we generate the first iteration with all input pcap files merged
    # shifted.
    first_iteration = f"{workdir}/iteration_1.pcap"
    merge_and_shift_pcap_files(
        pcap_files, first_iteration, pcap_format, offset
    )
    pcap_to_be_merged = [first_iteration]
    if len(pcap_files) > 1:
        # We copy the first pcap iteration n -1 times
        for i in range(2, iterations + 1):
            pcap_file = f"{workdir}/iteration_{i}.pcap"
            shutil.copyfile(first_iteration, pcap_file)
            pcap_to_be_merged.append(pcap_file)

    # Then we merge and shift all the iterations together
    merge_and_shift_pcap_files(
        pcap_to_be_merged,
        output,
        pcap_format,
        offset,
        verbose=True,
    )
    for pcap_file in pcap_to_be_merged:
        os.remove(pcap_file)
    os.rmdir(workdir)


if __name__ == "__main__":
    main()
