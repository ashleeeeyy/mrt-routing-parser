# Made by Ashley Statuto <ashley@statuto.org> in Janurary of 2021
import hashlib
import math
import sys
import datetime
import gzip
import wget


def uint_from_bytes(bytes):
    return int.from_bytes(bytes, "big", signed=False)
# A prefix entry
# prefix: 1.4.217.0 -> decimal
# prefix_length: 24
# announced_by: [23969]
# paths: list of lists [['as_1','as_2'], ['as_1','as_2','as_3']]
prefixes = {}

# ASN Peers
# asn: peers
# 13335 : [123,4123,123124,123123]
peer_listings = {}
collectors = ['00', '11']
for collector in collectors:
    print("Downloading collector", collector, "data...")
    wget.download("https://data.ris.ripe.net/rrc"+collector+"/latest-bview.gz",
                  out="dl/" + collector + "-latest-bview.gz")
    f = gzip.open("dl/" + collector+"-latest-bview.gz", "rb", 1024)

    z = 0
    i = 0

    # Do stuff with byte.

    begin_time = datetime.datetime.now()
    while True:
        ts = f.read(4)
        if not ts:
            break
        timestamp = uint_from_bytes(ts)
        msgtype = uint_from_bytes(f.read(2))
        subtype = uint_from_bytes(f.read(2))
        length = uint_from_bytes(f.read(4))

        if 2 <= subtype <= 5:

            #every prefix

            sequence_number = uint_from_bytes(f.read(4))
            prefix_length = uint_from_bytes(f.read(1))


            ip_length = math.ceil(prefix_length/8)
            if prefix_length == 0:
                ip_length = 1
                f.read(length-5)
                continue

            prefix = uint_from_bytes(f.read(ip_length))

            entry_count = uint_from_bytes(f.read(2))

            if entry_count == 0:
                f.read(1)

            # every routing table entry for this prefix
            paths = []
            announced_by = []
            for entry in range(entry_count):
                peer_index = uint_from_bytes(f.read(2))
                originated_time = uint_from_bytes(f.read(4))
                attrib_length = uint_from_bytes(f.read(2))

                as_sequence = []
                while attrib_length > 0:
                    flag = uint_from_bytes(f.read(1))


                    ext_len = (flag & 0b00010000) == 0b00010000
                    t = uint_from_bytes(f.read(1))

                    attrib_length -= 2
                    if ext_len:
                        value_len = uint_from_bytes(f.read(2))
                        attrib_length -= 2
                    else:
                        value_len = uint_from_bytes(f.read(1))
                        attrib_length -= 1

                    if t == 2:
                        # for every as_sequence

                        while value_len > 0:
                            asp_t = uint_from_bytes(f.read(1))
                            asp_len = uint_from_bytes(f.read(1))
                            value_len -= 2
                            attrib_length -= 2

                            for as_i in range(asp_len):
                                as_n = uint_from_bytes(f.read(4))
                                value_len -= 4
                                attrib_length -= 4
                                as_sequence.append(as_n)
                        for asn in as_sequence:
                            if asn not in peer_listings:
                                peer_listings[asn] = []

                        for j in range(0, len(as_sequence), 2):
                            asn = as_sequence[j]
                            # if we have an entry for this asn
                            peers = peer_listings[asn]

                            if j + 1 < len(as_sequence):
                                potential_peer = as_sequence[j + 1]
                                if potential_peer not in peers:
                                    peers.append(potential_peer)

                                    potential_peers_peers = peer_listings[potential_peer]
                                    if asn not in potential_peers_peers:
                                        potential_peers_peers.append(asn)
                                    peer_listings[potential_peer] = potential_peers_peers

                            peer_listings[asn] = peers

                    elif t != 2:
                        f.read(value_len)
                        attrib_length -= value_len
                # we now have the as sequence for $prefix
                # paths.append(as_sequence)
                if as_sequence[-1] not in announced_by:
                    announced_by.append(as_sequence[-1])
                # print("prefix:", prefix + "/" + str(prefix_length), "takes path", as_sequence)

                # average = average_dataset(as_sequence_len_history, 10, len(as_sequence))

                if i == 10000:
                    # every 1000 items dump that stuff into the db cuz hell ya
                    msg = ("Routes read: " + str(i * z))
                    sys.stdout.write('\r' + msg)

                    i = 0
                    z += 1
                i += 1

            ip_version = 4
            if subtype == 4 or subtype == 5:
                ip_version = 6
            this_prefix = {
                "prefix": prefix,
                "prefix_length": prefix_length,
                "announced_by": announced_by,
                "ipversion": ip_version,
                "paths": paths
            }
            pfxhsh = hashlib.md5((str(prefix)+"/"+str(prefix_length)).encode()).hexdigest()
            if pfxhsh in prefixes:
                prefixes[pfxhsh]["announced_by"] += announced_by
                prefixes[pfxhsh]["paths"] += paths
            else:
                prefixes[pfxhsh] = this_prefix
        elif subtype == 1:
            # load peers
            f.read(4)
            view_name_len = uint_from_bytes(f.read(2))
            f.read(view_name_len)
            peercount = uint_from_bytes(f.read(2))
            #print("PEERCOUNT: ", peercount)

            for i in range(peercount):
                peer_type = uint_from_bytes(f.read(1))
                peer_as_size = 4 if (peer_type & 0b00000010 == 2) else 2
                peer_ip_size = 16 if (peer_type & 0b00000001 == 1) else 4
                peer_bgp_id = uint_from_bytes(f.read(4))
                peer_ip_number = uint_from_bytes(f.read(peer_ip_size))
                peer_as_number = uint_from_bytes(f.read(peer_as_size))
                #print("IP ", peer_ip_number)
                #print("AS ", peer_as_number)
        else:
            f.read(length)

    print("Done Reading Dump1 Took", datetime.datetime.now() - begin_time)
    print("Prefix count:", len(prefixes))
    print("ASNs catalogued", len(peer_listings))
    print("3356s peers", len(peer_listings[3356]))

# Now we put it into the database
#################
# PREFIX_TABLE
################
# Prefix    | Prefix Length | Announcer | IPVersion
# --------------------------------------------------
# 1.0.0.0   | 8             | 13335     | 4

#################
# PEERING_PAIRS
################
# ASN | Peer
# ----------
# 173 | 28933
# etc...

##################
# AS_ASSIGNMENTS
##################
# ASN | Org. Name | ContactJSON
# etc..

