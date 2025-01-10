#!/bin/bash -e
#
# Copyright (C) 2023 Savoir-faire Linux, Inc.
# © 2023 GE Vernova and/or its affiliates. All rights reserved.
# This program is distributed under the Apache 2 license.

print_usage()
{
cat <<EOF
This script concatenate and repeat two pcap files

./$0 [OPTIONS]

options:
   -a first 1A file
   -b second 2A file
   -o output file
   -n iterations
   -h display this help message
EOF
}

die()
{
	local err="$1"
	echo "Error: $err"
	exit 1
}

# Name:       parse_options
# Brief:      Parse options from command line
# Param[in]:  Command line parameters
parse_options() {
    ARGS=$(getopt -o "a:b:o:n:h" -n "generate_pcap.sh" -- "$@")

    # Bad arguments
    if [ $? -ne 0 ]; then
        exit 1
    fi

    eval set -- "$ARGS"

    while true; do
        case "$1" in
            -a)
                if [ ! -f "$2" ]; then
                    echo "Fatal: A file does not exist" >&2
                    exit 1
                fi
                export A_file=$(readlink -f "$2")
                shift 2
                ;;
            -b)
                if [ ! -f "$2" ]; then
                    echo "Fatal: B file does not exist" >&2
                    exit 1
                fi
                export B_file=$(readlink -f "$2")
                shift 2
                ;;
            -n)
                export NB_ITERATION="$2"
                shift 2
                ;;
            -o)
                export OUTPUT_FILE="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "Invalid option" >&2
                print_usage
                exit 1
                ;;
        esac
    done
}

merge_pcap_a_and_b()
{
	local duration_a="$1"
	local merged_file="$2"
	local b_file_shifted=$(mktemp)
	editcap -t $duration_a "$B_file" "$b_file_shifted"
	mergecap -w "$merged_file" "$A_file" "$b_file_shifted"
	rm $b_file_shifted
}

generate_offset_pcap_file()
{
	local offset="$1"
	local src_pcap="$2"
	local out_pcap="$3"

	if [ "$offset" -eq 0 ];
	then
		cp "$src_pcap" "$out_pcap.$offset"
		return
	else
		editcap -t "$offset" "$src_pcap" "$out_pcap.$offset"
	fi
}
##########################
########## MAIN ##########
##########################

# Parse options
parse_options "$@"

if [ -z "$A_file" ] || [ -z "$B_file" ] || [ -z "$NB_ITERATION" ] || [ -z "$OUTPUT_FILE" ]
then
	print_usage
	exit 1
fi

echo "A_file" = "$A_file"
echo "B_file" = "$B_file"
echo "NB_ITERATION" = "$NB_ITERATION"
echo "OUTPUT_FILE" = "$OUTPUT_FILE"

WORK_DIR_NAME=".work"
mkdir -p $WORK_DIR_NAME || die "can not create .work dir"
WORK_DIR=$(readlink -f $WORK_DIR_NAME)
PCAP_SRC="$WORK_DIR/src.pcap"
PCAP_OUT="$WORK_DIR/out.pcap"

#A_file and B_file is supposed to have 1s
#TODO: get dynamically the value
duration_a_file=1
merge_pcap_a_and_b $duration_a_file $PCAP_SRC || die "can not merge A and B"
offset=0

for i in $(seq 1 $NB_ITERATION);
do
	echo "[$i/$NB_ITERATION] edit"
	generate_offset_pcap_file "$offset" "$PCAP_SRC" "$PCAP_OUT"
	#each $PCAP_SRC has a duration of 1+1=2seconds
	#TODO: get dynamically the value
	offset=$(expr $offset + 2)
done
echo "merging $NB_ITERATION files into $OUTPUT_FILE"
mergecap -w "$OUTPUT_FILE" $PCAP_OUT*
tshark -r $OUTPUT_FILE -w $WORK_DIR/tmp.pcap -F libpcap
echo "cleaning"
rm -r "$WORK_DIR"
