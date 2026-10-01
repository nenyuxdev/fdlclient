#!/usr/bin/env python3
import argparse
import os
import struct
import sys

os.system('')

BANNER = """\x1b[1;32m
  ___ ___  _        ___ _    ___ ___ _  _ _____ 
 | __|   \\| |      / __| |  |_ _| __| \\| |_   _|
 | _|| |) | |__   | (__| |__ | || _|| .` | | |  
 |_| |___/|____|   \\___|____|___|___|_|\\_| |_|  
                                                
\x1b[0m\x1b[1;36m FDL Client By nenyuxdev\x1b[0m
"""

PAC_HEADER_FMT = '44s I I 512s 512s I I I I I I I 200s I I I 800s I H H'
FILE_HEADER_FMT = 'I 512s 512s 504s I I I I I I I I 5I 996s'


def get_string(raw_bytes):
    return raw_bytes.decode('utf-16le', errors='ignore').rstrip('\x00')


def extract_fdls(pac_file, out_dir=None):
    print(BANNER)

    if not os.path.isfile(pac_file):
        sys.exit(f"Error: File '{pac_file}' does not exist.")

    if out_dir is None:
        out_dir = os.path.join(os.getcwd(), 'fdls')

    os.makedirs(out_dir, exist_ok=True)

    with open(pac_file, 'rb') as f:
        pac_hdr_size = struct.calcsize(PAC_HEADER_FMT)
        pac_data = f.read(pac_hdr_size)

        if len(pac_data) < pac_hdr_size:
            sys.exit("Error: Invalid PAC header.")

        unpacked_pac = struct.unpack(PAC_HEADER_FMT, pac_data)
        
        sz_version = get_string(unpacked_pac[0])
        partition_count = unpacked_pac[5]
        partitions_offset = unpacked_pac[6]

        if sz_version not in ('BP_R1.0.0', 'BP_R2.0.1'):
            sys.exit(f"Error: Unsupported PAC version ({sz_version}).")

        f.seek(partitions_offset)
        file_hdr_size = struct.calcsize(FILE_HEADER_FMT)

        fdl_entries = []

        for _ in range(partition_count):
            file_data = f.read(file_hdr_size)
            if len(file_data) < file_hdr_size:
                break

            unpacked_file = struct.unpack(FILE_HEADER_FMT, file_data)

            partition_name = get_string(unpacked_file[1])
            file_name = get_string(unpacked_file[2])
            
            hi_size = unpacked_file[4]
            hi_offset = unpacked_file[5]
            lo_size = unpacked_file[6]
            lo_offset = unpacked_file[9]

            file_size = (hi_size << 32) + lo_size
            data_offset = (hi_offset << 32) + lo_offset

            name_upper = partition_name.upper()
            fname_upper = file_name.upper()

            if 'FDL' in name_upper or 'FDL' in fname_upper:
                if file_size == 0:
                    continue

                if '2' in name_upper or '2' in fname_upper:
                    display_name = partition_name
                    target_name = "fdl2.bin"
                    sort_key = 2
                else:
                    display_name = "FDL1"
                    target_name = "fdl1.bin"
                    sort_key = 1

                fdl_entries.append({
                    'sort_key': sort_key,
                    'display_name': display_name,
                    'target_name': target_name,
                    'file_size': file_size,
                    'data_offset': data_offset
                })

        if not fdl_entries:
            print("No FDL files found.")
            return

        fdl_entries.sort(key=lambda x: x['sort_key'])

        for entry in fdl_entries:
            f.seek(entry['data_offset'])
            fdl_bytes = f.read(entry['file_size'])

            out_path = os.path.join(out_dir, entry['target_name'])
            with open(out_path, 'wb') as out_f:
                out_f.write(fdl_bytes)

            size_kb = entry['file_size'] / 1024
            size_str = f"{entry['file_size']} B" if entry['file_size'] < 1024 else f"{size_kb:.1f} KB"
            print(f"{entry['display_name']:<10} -> {entry['target_name']:<10} ({size_str})")

    print("\nDone...")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FDL Client - PAC Extractor')
    parser.add_argument('pacfile', help='Path to .pac file')
    parser.add_argument('outdir', nargs='?', help='Output directory', default=None)

    args = parser.parse_args()
    extract_fdls(args.pacfile, args.outdir)