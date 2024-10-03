<!--Copyright (C) 2024 Savoir-faire Linux, Inc.
SPDX-License-Identifier: Apache-2.0 -->

# sv-pcap-generator

sv-pcap-generator is a tool used to generate IEC61850 Sample Values
PCAP (Packet Capture) files. You can then replicate IEC61850 SV trafic
on a network using tools such as `bittwist` or `tcpreplay`.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Release notes](#release-notes)

## Introduction
## Features

- Generation of SV PCAP files along various IEC61850 parameters
  (frequency, appid, number of streams, etc)
- IEC61850 compliant pacing (250µs for 50Hz electrical network, 208µs
  for 60Hz electrical network)
- Supports pcap loopback to make longer trafic generation

## Installation
### Requirements

Following Python packages are needed:
```bash
pip install numpy
```

To run merge_pcap script, `wireshark` package is needed.
## Usage

To generate a IEC61850 SV pcap on 8 streams, with 4000 SV for each
streams, for a 50Hz electrical network, run:

```bash
python3 generate_pcap.py -n 8 -l 4000 -f 50 output.pcap
```

Optionally, you can run `merge_pcap.sh` script to buckle a generated
pcap with himself, and thus, make bigger pcap files.

To do so, run:

```bash
./merge_pcap.sh -a output.pcap -b output.pcap -o merged_output.pcap -n 10
```

This command will buckle the pcap file `output.pcap` with itself on
10 iterations.

## Release notes
### Version v0.1
Initial release
