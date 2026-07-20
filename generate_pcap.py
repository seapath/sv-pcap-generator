#!/usr/bin/env python3
# © 2023 GE Vernova and/or its affiliates. All rights reserved.
# 2026 improved by Jose Saldana at CIRCE Technology center

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

parser.add_argument(
    "-m",
    "--nb_asdu",
    type=int,
    help="Number of ASDUs (streams) bundled together in a single frame. "
    "nb_streams streams are packed into ceil(nb_streams/nb_asdu) frames "
    "per loop iteration.",
    default=1,
)

parser.add_argument("-p", "--svID_prefix", type=str, help="SV ID prefix", default="svID")

parser.add_argument("-d", "--svID_digits", type=int, help="Number of SV ID digits", default=4)

parser.add_argument(
    "-l",
    "--loop",
    type=int,
    help="Number of iterations."
    "The smpCnt field will be increased at each loop",
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
    "--mac_source",
    type=str,
    help="Source MAC address",
    default="c4:b5:12:00:00:01",
)

parser.add_argument(
    "--mac_dest",
    type=str,
    help="Destination MAC address",
    default="01:0c:cd:01:00:01",
)

parser.add_argument(
    "--vlanID",
    type=int,
    help="VLAN ID. 0 to disable VLAN",
    default=0,
)

parser.add_argument(
    "--vlanPriority",
    type=int,
    help="VLAN Priority",
    default=4,
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
nb_asdu = args.nb_asdu
max_counter = args.loop
i_rms = args.i_rms
v_rms = args.v_rms
nb_digits = args.svID_digits
svID_max = 10 ** nb_digits - 1
svID_prefix = args.svID_prefix
mac_source = args.mac_source
mac_dest = args.mac_dest
vlanID = args.vlanID
vlanPriority = args.vlanPriority

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

if nb_asdu < 1 or nb_asdu > 255:
    # NumOfASDU is encoded on a single byte (0x80 0x01 value), so it is
    # limited to 255 ASDUs per frame.
    print("Error nb_asdu must be between 1 and 255", file=sys.stderr)
    sys.exit(1)

if nb_asdu > nb_streams:
    print("Error nb_asdu must be lower than or equal to nb_streams", file=sys.stderr)
    sys.exit(1)

if max_counter < 1 or max_counter > 65536:
    print("Error loop must be between 1 and 65536", file=sys.stderr)
    sys.exit(1)

if freq <= 0:
    print("Error frequency must be greater than 0", file=sys.stderr)
    sys.exit(1)

if len(mac_source) != 17 or len(mac_dest) != 17:
    print("Error MAC address must be in the format XX:XX:XX:XX:XX:XX", file=sys.stderr)
    sys.exit(1)

def mac_string_to_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))

# Check if the MAC address is valid
try:
    mac_source = mac_string_to_bytes(mac_source)
    mac_dest = mac_string_to_bytes(mac_dest)
except ValueError:
    print("Error MAC address must be in the format XX:XX:XX:XX:XX:XX", file=sys.stderr)
    sys.exit(1)

if vlanID < 0 or vlanID > 4095:
    print("Error VLAN ID must be between 0 and 4095", file=sys.stderr)
    sys.exit(1)

if vlanPriority < 0 or vlanPriority > 7:
    print("Error VLAN Priority must be between 0 and 7", file=sys.stderr)
    sys.exit(1)

PCAP_GLOBAL_HEADER = (
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x04\x00\x01\x00\x00\x00"
)

if vlanID != 0:
    # 802.1Q VLAN Tag Header
    # 0x8100: 802.1Q VLAN Tag Protocol Identifier
    # Priority Code Point (PCP) (3 bits) | CFI (1 bit) | VLAN Identifier (12 bits)
    tpid = 0x8100
    tci = (vlanPriority << 13) | vlanID
    vlan_header = struct.pack("!HH", tpid, tci)
else:
    vlan_header = b""

ETHERTYPE_SV = b"\x88\xBA"

CONF_REV_TLV = b"\x83\x04\x00\x00\x00\x01"
SMP_SYNC_TLV = b"\x85\x01\x00"


def get_second_microsecond(ts):
    second = int(ts)
    microsecond = int(round((ts - second) * 1000000))
    return (second, microsecond)


def ber_length(n):
    """Encode a length in BER/DER definite form (short or long form)."""
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def build_asdu(svID, smpCnt, sample_data):
    """Build a single ASDU (tag 0x30) TLV containing SvID, SmpCnt, ConfRev,
    SmpSynch and the sequence of data samples."""
    svid_tlv = b"\x80" + bytes([len(svID)]) + svID.encode("ascii")
    smpcnt_tlv = b"\x82\x02" + struct.pack(">H", smpCnt)
    seq_of_data_tlv = b"\x87" + ber_length(len(sample_data)) + sample_data
    content = svid_tlv + smpcnt_tlv + CONF_REV_TLV + SMP_SYNC_TLV + seq_of_data_tlv
    return b"\x30" + ber_length(len(content)) + content


def build_savpdu(asdus):
    """Build the savPDU (tag 0x60): NumOfASDU + SeqOfASDU (containing all
    the ASDUs passed in)."""
    seq_content = b"".join(asdus)
    num_of_asdu_tlv = b"\x80\x01" + bytes([len(asdus)])
    seq_of_asdu_tlv = b"\xa2" + ber_length(len(seq_content)) + seq_content
    content = num_of_asdu_tlv + seq_of_asdu_tlv
    return b"\x60" + ber_length(len(content)) + content


def build_sv_pdu(app_id, savpdu):
    """Build the SV common header (AppID, Length, Reserved1, Reserved2)
    followed by the savPDU. Length covers the whole SV PDU (itself
    included)."""
    total_length = 8 + len(savpdu)  # AppID(2)+Length(2)+Reserved1(2)+Reserved2(2)+savPDU
    header = (
        struct.pack(">H", app_id)
        + struct.pack(">H", total_length)
        + b"\x00\x00\x00\x00"  # Reserved1 & Reserved2
    )
    return header + savpdu


def build_samples(i, sampling_rate):
    """Compute the 64 bytes (8 channels x (4 bytes sample + 4 bytes
    quality)) sequence of data for sample index i."""
    data = bytearray()
    for index, channel in enumerate(current_channels):
        if channel != "In":
            signal = int(
                scale_factor_amps
                * i_rms
                * np.sqrt(2)
                * np.sin(
                    (2 * np.pi * freq * i / sampling_rate)
                    + ((2 * np.pi / 3) * index)
                )
            )
        else:
            signal = 0
        data += signal.to_bytes(4, byteorder="big", signed=True)
        data += b"\x00\x00\x00\x00"
    for index, channel in enumerate(voltage_channels):
        if channel != "Vn":
            signal = int(
                scale_factor_volts
                * v_rms
                * np.sqrt(2)
                * np.cos(
                    (2 * np.pi * freq * i / sampling_rate)
                    + ((2 * np.pi / 3) * index)
                )
            )
        else:
            signal = 0
        data += signal.to_bytes(4, byteorder="big", signed=True)
        data += b"\x00\x00\x00\x00"
    return bytes(data)


def build_frame(app_id, asdus):
    """Build a full pcap record (record header + Ethernet frame carrying
    the SV PDU with the given list of ASDUs), timestamp not yet set."""
    savpdu = build_savpdu(asdus)
    sv_pdu = build_sv_pdu(app_id, savpdu)
    eth_frame = mac_dest + mac_source + vlan_header + ETHERTYPE_SV + sv_pdu
    return eth_frame


samples_per_cyle = 80
sampling_rate = samples_per_cyle * freq
scale_factor_amps = 1000
scale_factor_volts = 100
voltage_channels = ["Va", "Vb", "Vc", "Vn"]
current_channels = ["Ia", "Ib", "Ic", "In"]

# Group the streams into chunks of nb_asdu streams: each chunk becomes one
# frame containing nb_asdu ASDUs (the last chunk may contain fewer ASDUs if
# nb_streams is not a multiple of nb_asdu).
stream_ids = list(range(start_id, start_id + nb_streams))
groups = [stream_ids[k : k + nb_asdu] for k in range(0, len(stream_ids), nb_asdu)]

pcap_data = bytearray()
pcap_data += PCAP_GLOBAL_HEADER

ts = 0
for i in range(0, max_counter):
    (second, microsecond) = get_second_microsecond(ts)
    ts = (i + 1) / sampling_rate
    smpCnt = i % int(sampling_rate)

    # Samples are identical across all streams/ASDUs at a given sample
    # index, so compute them once per loop iteration.
    sample_data = build_samples(i, sampling_rate)

    for group in groups:
        asdus = []
        for st in group:
            svID = f"{svID_prefix}{st:0{nb_digits}d}"
            asdus.append(build_asdu(svID, smpCnt, sample_data))

        eth_frame = build_frame(app_id, asdus)
        frame_len = len(eth_frame)

        # pcap per-packet record header:
        # ts_sec(4) ts_usec(4) incl_len(4) orig_len(4), all little-endian.
        # +1 offset on second/microsecond to avoid a tcpreplay limitation:
        # tcpreplay does not support frames with a 0 timestamp.
        record_header = struct.pack(
            "<IIII", second + 1, microsecond + 1, frame_len, frame_len
        )

        pcap_data += record_header
        pcap_data += eth_frame

with open(final_pcap, "wb") as f:
    f.write(pcap_data)
