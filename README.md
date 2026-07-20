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

### Improvements 2026

- New `-m/--nb_asdu` option: number of ASDUs (streams) bundled into a single frame. `nb_streams` is chunked into groups of this size (the last group can be smaller if it doesn't divide evenly), and each group becomes one frame.

- Dynamic BER length encoding: the original code hard-coded single-byte lengths (e.g. `0x6` + len(svIDFirst)`), which only worked because there was always exactly one ASDU. Bundling multiple ASDUs easily pushes lengths past 127 bytes, so a proper `ber_length()` helper has been added that emits short-form or long-form BER lengths as needed, used for every TLV (ASDU, SeqOfASDU, savPDU, SeqOfData).

- Frames are built bottom-up per iteration: `build_asdu()` → `build_savpdu()` → `build_sv_pdu()` → `Ethernet` frame, then wrapped in a correctly-sized pcap record header (also switched the pcap `incl_len/orig_len` to proper 4-byte little-endian fields instead of the single-byte-with-zero-padding trick, since frame sizes now regularly exceed 255 bytes).

- Samples are computed once per loop iteration and reused across all ASDUs/frames at that timestamp, matching the original's behavior (same waveform value regardless of stream).
Added validation: `nb_asdu` must be 1–255 (the `NumOfASDU` field is a single byte) and ≤ nb_streams.


## Installation
### Requirements

Following Python packages are needed:
```bash
pip install numpy
```

To run merge_pcap script, `wireshark` package is needed.
## Usage

### Example 1
To generate a IEC61850 SV pcap on 8 streams, with 4000 SV for each
streams, for a 50Hz electrical network, run:

```bash
python3 generate_pcap.py -n 8 -l 4000 -f 50 output.pcap
```

### Example 2

```bash
python3 gen_sv_pcap.py -n 96 -m 6 -l 4000 -f 60 sv_6asdu.pcap
```

Breakdown of the flags:

`-n 96` — total number of streams (96 here just so it divides evenly into groups of 6; use whatever you actually need)
`-m 6` — bundle 6 ASDUs per frame, so this produces 96 / 6 = 16 frames per loop iteration
`-l 4000` — 4000 loop iterations (default)
`-f 60` — 60 Hz sampling frequency (default)
`sv_6asdu.pcap` — output file

If you want to keep all your other defaults (`start_id`, `svID` prefix/digits, RMS values, MAC addresses, `VLAN`, etc.), you can just add `-m 6` to whatever command you were already running, e.g.:

```bash
python3 gen_sv_pcap.py -n 64 -m 6 output.pcap
```
Note `64` isn't evenly divisible by 6, so this gives you ten frames of 6 ASDUs plus a final frame of 4 ASDUs per loop iteration — the script handles that remainder automatically rather than erroring out.


Optionally, you can run `merge_sv_pcap.py` script to merged multiple SV pcap
file. This is useful to generate discontinuity to test electrical lines
protections.

To do so, run:

```bash
./merge_sv_pcap.py 1.pcap 2.pcap 3.pcap -o merged.pcap -f 50
```

The `merge_sv_pcap.py` can be also used to repeat a pcap multiple time with `-n`
argument

```bash
./merge_sv_pcap.py my_sv_recored.pcap -o 10_interations.pcap -n 10 -f 50
```

In both case a delay between the merged pcap is inserted base on the current
frequency.


## Release notes
### Version v0.1
 * Initial release

### Version v1.0.0

* Rewrite merge_pcap in Python
* Improve merge_pcap to support multiple pcap with different duration
* Add VLAN ID, Priority and MAC addresses options
