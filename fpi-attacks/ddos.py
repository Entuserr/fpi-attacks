

from scapy.all import TCP, IP, raw

def perform(packets, shark):
    src_ips = {}
    n_ack_syn = 0
    indices = []
    for i, p in enumerate(packets):
        if p.haslayer(TCP):
            #SYN/ASK or RST/FIN
            flags = p.getlayer(TCP).flags
            if (flags & 0x12 != 0) or (flags & 0x05 != 0):
                indices.append(i+1)
                n_ack_syn += 1;
                src_ips[p.getlayer(IP).src] = 1

    score = 0.0
    if len(src_ips) > 10:
        score = 1.0

    return (score, indices, 2, "TCP-DDOS")