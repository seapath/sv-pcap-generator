#!/usr/bin/env python3
# © 2023 GE Vernova and/or its affiliates. All rights reserved.

import sys
import struct
import argparse
import numpy as np

parser = argparse.ArgumentParser(description="Generate IEC 61850 SV streams")

parser.add_argument(
    "-a", "--app_id", type=int, help="SV stream APPID", default=16384  # 0x4000
)

parser.add_argument(
    "-s", "--start_id", type=int, help="start index of svID streams", default=0
)

parser.add_argument(
    "-n", "--nb_streams", type=int, help="Number of SV streams", default=64
)

parser.add_argument("-p", "--svID_prefix", type=str, help="SV ID prefix", default="svID")

parser.add_argument("-d", "--svID_digits", type=int, help="Number of SV ID digits", default=4)

parser.add_argument(
    "-l",
    "--loop",
    type=int,
    help="Number of iterations."
    "The cmpCnt field will be increased at each loop",
    default=4000,
)

parser.add_argument(
    "-f", "--frequency", type=float, default=60, help="Loop frequency"
)

parser.add_argument(
    "-i",
    "--i_rms",
    type=float,
    default=1,
    help="RMS desired for Current channels",
)

parser.add_argument(
    "-v",
    "--v_rms",
    type=float,
    default=57,
    help="RMS desired for Voltage channels",
)

parser.add_argument(
    "output",
    type=str,
    help="Path to the output pcap file which can be replayed using tcpreplay",
)

args = parser.parse_args()

freq = args.frequency
final_pcap = args.output
app_id = args.app_id
start_id = args.start_id
nb_streams = args.nb_streams
max_counter = args.loop
i_rms = args.i_rms
v_rms = args.v_rms
nb_digits = args.svID_digits
svID_max = 10 ** nb_digits - 1
svID_prefix = args.svID_prefix

try:
    svID_prefix.encode("ascii")
except UnicodeEncodeError:
    print("Error svID_prefix must be an ASCII string", file=sys.stderr)
    sys.exit(1)

if nb_digits < 1 or nb_digits > 8:
    print("Error nb_digits must be between 1 and 8", file=sys.stderr)
    sys.exit(1)

if app_id < 0x4000 or app_id > 0x4FFF:
    print("Error app_id must be between 0x4000 and 0x4FFFF", file=sys.stderr)
    sys.exit(1)

if start_id < 0 or start_id + nb_streams > svID_max:
    print("Error in start_id", file=sys.stderr)
    sys.exit(1)

if nb_streams > svID_max or nb_streams < 1:
    print(f"Error nb_streams must be between 1 and {svID_max}", file=sys.stderr)
    sys.exit(1)

if max_counter < 1 or max_counter > 65536:
    print("Error loop must be between 1 and 65536", file=sys.stderr)
    sys.exit(1)

if freq <= 0:
    print("Error frequency must be greater than 0", file=sys.stderr)
    sys.exit(1)

HEADER = (
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x04\x00\x01\x00\x00\x00"
)

start_id_str = f"{start_id:0{nb_digits}d}"
svIDFirst = svID_prefix + start_id_str

# This data are generated from an pcap file
# It is possible to change the SV to sent. The only restriction is that the
# SV ID must have 8 bytes lenght and must contains only one ASDU
# To change this:
# 1. Capture an SV using Wireshark or tcpdump and generate a pcap file with
#    times in µs. The file must contained only one SV
# 2. Drop the pcap header (0 to 0x18)
# 3. Set timestamp to 0 (set the next 8 bytes to 0)
# 5. At offset 0x28 Ensure the MAC Address destination is a IEEE 802.1X
#    Multicast sampled values address (01:0C:CD:04:00:00 to 01:0C:CD:04:01:FF)
# 6. Adjust in the SV_ID_OFFSET and CMP_CNT_OFFSET in this file

SV_DATA = (
    # Timestamp
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # Packet length
    + bytes([0x70 + len(svIDFirst)]) + b"\x00\x00\x00"
    # Capture length
    + bytes([0x70 + len(svIDFirst)]) + b"\x00\x00\x00"
    # Destination MAC
    b"\x01\x0c\xcd\x01\x00\x01"
    # Source MAC
    b"\xc4\xb5\x12\x00\x00\x01"
    # Ethertype
    b"\x88\xBA"
    # AppId
    b"\x40\x00"
    # Length
    b"\x00" + bytes([0x62 + len(svIDFirst)]) +
    # Reserved 1 & Reserved 2
    b"\x00\x00\x00\x00"
    # savPDU 0x60 Length
    b"\x60" + bytes([0x58 + len(svIDFirst)]) +
    # Number of asdu 0x80 L(1) 8
    b"\x80\x01\x01"
    # Sequence of asdu 0xA2 L
    b"\xa2" + bytes([0x53 + len(svIDFirst)]) +
    # Sequence ASDU1 0x30 L
    b"\x30" + bytes([0x51 + len(svIDFirst)]) +
    # SvID 0x80 L Values
    b"\x80" + bytes([len(svIDFirst)]) + svIDFirst.encode("ascii") +
    # smpCnt 0x82 L(2) value
    b"\x82\x02\x00\x00"
    # ConfRev 0x83 L(4) value
    b"\x83\x04\x00\x00\x00\x01"
    # smpSync 0x85 L(1) value
    b"\x85\x01\x00"
    # Sequence of Data 0x87 L(64) Dataset 8 CH
    # (4 bytes sample + 4 bytes quality)
    b"\x87\x40"
    # b"\x00\x00\x00\x01\x00\x00\x00\x00"
    # b"\x00\x00\x00\x02\x00\x00\x00\x00"
    # b"\x00\x00\x00\x03\x00\x00\x00\x00"
    # b"\x00\x00\x00\x04\x00\x00\x00\x00"
    # b"\x00\x00\x00\x05\x00\x00\x00\x00"
    # b"\x00\x00\x00\x06\x00\x00\x00\x00"
    # b"\x00\x00\x00\x07\x00\x00\x00\x00"
    # b"\x00\x00\x00\x08\x00\x00\x00\x00"
)

TS_OFFSET = 0
APP_ID_OFFSET = 0x1E
SV_ID_OFFSET = 0x31
SMP_CNT_OFFSET = SV_ID_OFFSET + 2 + len(svIDFirst)


def get_second_microsecond(ts):
    second = int(ts)
    microsecond = int(round((ts - second) * 1000000))
    return (second, microsecond)


def write_bytes_le(sv, offset, data, len=-2):
    for i in data:
        if len == -1:
            break
        sv[offset] = i
        offset += 1
        if len > 0:
            len -= 1


def write_bytes_be(sv, offset, data):
    offset += len(data) - 1
    for i in data:
        sv[offset] = i
        offset -= 1


pcap_data = bytearray()

# Add header
pcap_data += HEADER

sv_data = bytearray(SV_DATA)
ts = 0
samples_per_cyle = 80
sampling_rate = samples_per_cyle * freq
scale_factor_amps = 1000
scale_factor_volts = 100
voltage_channels = ["Va", "Vb", "Vc", "Vn"]
current_channels = ["Ia", "Ib", "Ic", "In"]
for i in range(0, max_counter):
    (second, microsecond) = get_second_microsecond(ts)
    ts = (i + 1) / sampling_rate
    # Write AppID
    write_bytes_be(
        sv_data, APP_ID_OFFSET, struct.pack("H", app_id)
    )
    # Write cmpCnt
    write_bytes_be(
        sv_data, SMP_CNT_OFFSET, struct.pack("H", (i % int(sampling_rate)))
    )
    # Write TS add a +1 offset to second and microsecond to avoid a tcpreplay
    # limitation. tcpreplay do not support frames with a 0 timestamp.
    write_bytes_le(
        sv_data, TS_OFFSET, struct.pack("II", second + 1, microsecond + 1)
    )
    for st in range(0, nb_streams):
        # svID string are svID_prefixXXXX
        svID_data = f"{svID_prefix}{start_id+st:0{nb_digits}d}".encode("ascii")
        write_bytes_le(sv_data, SV_ID_OFFSET, svID_data, len(svID_data) - 1)
        pcap_data += sv_data
        for index, channel in np.ndenumerate(current_channels):
            # 4 bytes of sample
            if channel != "In":
                signal = int(
                    scale_factor_amps
                    * i_rms
                    * np.sqrt(2)
                    * np.sin(
                        (2 * np.pi * freq * i * (1 / sampling_rate))
                        + ((2 * np.pi / 3) * index[0])
                    )
                )
            else:
                signal = 0
            pcap_data += bytearray(
                signal.to_bytes(4, byteorder="big", signed=True)
            )
            # 4 bytes of quality
            pcap_data += bytearray(b"\x00\x00\x00\x00")
        for index, channel in np.ndenumerate(voltage_channels):
            # 4 bytes of sample
            if channel != "Vn":
                signal = int(
                    scale_factor_volts
                    * v_rms
                    * np.sqrt(2)
                    * np.cos(
                        (2 * np.pi * freq * i * (1 / sampling_rate))
                        + ((2 * np.pi / 3) * index[0])
                    )
                )
            else:
                signal = 0
            pcap_data += bytearray(
                signal.to_bytes(4, byteorder="big", signed=True)
            )
            # 4 bytes of quality
            pcap_data += bytearray(b"\x00\x00\x00\x00")

with open(final_pcap, "wb") as f:
    f.write(pcap_data)
