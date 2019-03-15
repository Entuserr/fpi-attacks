
import csv, sys
from tools.ngram import NGram, updateNGram
from os import listdir, makedirs
from scapy.all import rdpcap
from scapy.all import raw, IP, TCP, UDP
from os.path import isfile, join, isdir, exists
from collections import Counter

def get_ngram_size():
    return 6

def get_features_n():
    return 9

def get_pck_features(p):
    feats = [0] * get_features_n()
    if TCP in p:
        ptcp = p[TCP]
        feats[1] = 1
        #feats[2] = 1 if p.seq == 1 else 0
        feats[3] = min(ptcp.sport, 1000)
        feats[4] = min(ptcp.dport, 1000)
        r_data = bytes(ptcp.payload)
    elif UDP in p:
        pudp = p[UDP]
        feats[1] = 2
        feats[3] = min(pudp.sport, 1000)
        feats[4] = min(pudp.dport, 1000)
        r_data = bytes(pudp.payload)
    else:
        r_data = raw(p)

    feats[0] = len(r_data)
    if len(r_data) > 0:
        mc = Counter(r_data).most_common(2)
        feats[5] = mc[0][0]
        feats[6] = mc[0][1] / len(r_data)
        if len(mc) > 1:
            feats[7] = mc[1][0]
            feats[8] = mc[1][1] / len(r_data)

    return r_data, feats

def build_streams(packets, is_atk):
    session_data = {}
    session_atk = {}
    session_feats = {}
    for i, p in enumerate(packets):
        if TCP in p:
            b = bytes(p[TCP].payload)
            if len(b) > 0:
                s_key = str([p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport])
                session = session_data.get(s_key);
                if session is None:
                    session = bytes()
                    session_data[s_key] = session
                    session_atk[s_key] = is_atk[i]
                    session_feats[s_key] = get_pck_features(p)
                session_data[s_key] = session + b
                if session_atk[s_key] != is_atk[i]:
                    print( "mixed stream detected : error" )
                is_atk[i] = -1
    return session_data, session_atk, session_feats



if __name__ == "__main__":

    input_dir = "../data/Attacks_train/"
    input_file = "../data/attacks_train.csv"
    output_dir = "./statistics/"

    if len(sys.argv) > 1:
        input_dir = sys.argv[1]
    if len(sys.argv) > 2:
        input_file = sys.argv[2]
    if len(sys.argv) > 3:
        output_dir = sys.argv[3]
    
    if not isdir(input_dir):
        print("Not a directory : %s" % input_dir)
        sys.exit(-1)
    if not exists(output_dir):
        makedirs(output_dir)
    if not isdir(output_dir):
        print("Not a directory : %s" % output_dir)
        sys.exit(-1)

    category_count = 6

    NSize = get_ngram_size()

    ngrams = NGram(NSize)

    categories = {}
    vulns = {}

    skip_cats = {2 : True, 4 : True}

    csv_file = open(input_file, 'r')
    with csv_file:  
        reader = csv.reader(csv_file, delimiter=';')
        next(reader)

        for r in reader:
            f = join(input_dir, r[0])
            print("Preprocessing : %s.. " % f)

            category = int(r[2])
            vuln = r[3]
            if category in skip_cats:
                continue

            categories[category] = 1
            vulns[vuln] = category

            indices = [int(x)-1 for x in r[1].strip()[1:-1].split(",")]

            packets = rdpcap(f)
            #packets = pyshark.FileCapture(f)

            is_atk = [0] * len(packets)
            for i in indices:
                is_atk[i] = 1

            #session_data, session_atk, session_feats = build_streams(packets, is_atk)
            session_data, session_atk, session_feats = ({}, {}, {})

            for k in session_data.keys():
                p_cat = category
                if session_atk[k] == 0: p_cat = 0
                ngrams.append(session_data[k], vuln if p_cat > 0 else None)

            n_single = 0
            for i, p in enumerate(packets):
                if is_atk[i] < 0: continue
                
                if TCP in p:
                    r_data = bytes(p[TCP].payload)
                elif UDP in p:
                    r_data = bytes(p[UDP].payload)
                else:
                    r_data = raw(p)
                if len(r_data) > 0:
                    n_single += 1
                    p_cat = category
                    if is_atk[i] == 0: p_cat = 0

                    ngrams.append(r_data, vuln if p_cat > 0 else None)
                
            #print("%d packets, %d single, %d sessions" % (len(packets), n_single, len(session_data)))
    
    print ("Processing zero class")
    ngrams.do_zero_class()

    chosen_grams = {}
    
    for vuln in vulns.keys():
        #print("Vulnerability vs others : %s" % vuln)
        others = [x for x in vulns.keys() if x != vuln]
        others.append("zero")
        bgrams = ngrams.get_best_grams(vuln, others, 8)
        #vulns[vuln] = bgrams
        for k in bgrams:
            print ("%s - %.3f (%d) %.3f * %.3f" % (k[0].hex(), k[1], k[2], k[3], k[4]))

        for k in bgrams:
            chosen_grams[k[0]] = (k[3], k[4], vuln + " vs all")
    
    for vuln in vulns.keys():
        others = [x for x in vulns.keys() if x != vuln and vulns[x] == vulns[vuln]]
        if len(others) > 0:
            #print("Vulnerability vs same class : %s" % vuln)
            bgrams = ngrams.get_best_grams(vuln, others, 6)

            for k in bgrams:
                print ("%s - %.3f (%d) %.3f * %.3f" % (k[0].hex(), k[1], k[2], k[3], k[4]))

            for k in bgrams:
                chosen_grams[k[0]] = (k[3], k[4], vuln + " vs class")

    #print("Total grams : %d" % len(chosen_grams))

    vuln_id = {}
    vuln_count_in_cat = [0] * category_count 
    vuln_count = 1
    vuln_id_global = {}

    for k, v in vulns.items():
        if k not in vuln_id:
            vuln_id_global[k] = vuln_count
            vuln_id[k] = vuln_count_in_cat[v] 
            vuln_count_in_cat[v] += 1
            vuln_count += 1

    #packet size, TCP/UDP, first packet in stream flag (if TCP), source port, dest port
    n_pck_features = get_features_n()

    n_features = len(chosen_grams) + n_pck_features

    csv_file = open(join(output_dir, "grams.csv"), 'w', newline = "")
    with csv_file:  
        writer = csv.writer(csv_file, delimiter=";")
        for i, g in enumerate(chosen_grams.keys()):
            writer.writerow([i, g.hex(), chosen_grams[g][0], chosen_grams[g][1], chosen_grams[g][2]])
            chosen_grams[g] = i

    csv_file = open(join(output_dir, "vulns.csv"), 'w', newline = "")
    with csv_file:  
        writer = csv.writer(csv_file, delimiter=";")
        for k, v in vulns.items():
            writer.writerow([k, v, vuln_id[k], vuln_id_global[k]])

    files = [open(join(output_dir, "train_%d.txt" % i), "w") for i in range(0, category_count)]

    file_all = open(join(output_dir, "train_all.txt"), "w")

    csv_file = open(input_file, 'r')
    with csv_file:  
        reader = csv.reader(csv_file, delimiter=';')
        next(reader)

        for r in reader:
            f = join(input_dir, r[0])
            print("Generating train data : %s.. " % f, end = "")

            category = int(r[2])
            vuln = r[3]
            if category in skip_cats:
                continue

            indices = [int(x)-1 for x in r[1].strip()[1:-1].split(",")]
            packets = rdpcap(f)
            is_atk = [0] * len(packets)
            for i in indices:
                is_atk[i] = 1

            for i, p in enumerate(packets):
                if is_atk[i] < 0: continue

                p_cat = category
                if is_atk[i] == 0: p_cat = 0

                feats = [0] * n_features

                r_data, p_feats = get_pck_features(p)
                for i in range(len(p_feats)): feats[i] = p_feats[i]

                layer = {}
                updateNGram(layer, r_data, NSize)
                for k, v in layer.items():
                    ng_id = chosen_grams.get(k)
                    if ng_id is None: continue
                    feats[ng_id+n_pck_features] = v

                files[0].write("%d " % p_cat)
                for j, v in enumerate(feats):
                    files[0].write("%d:%.3f " % (j+1, v))
                files[0].write("\n")

                file_all.write("%d " % (0 if p_cat == 0 else vuln_id_global[vuln]))
                for j, v in enumerate(feats):
                    file_all.write("%d:%.3f " % (j+1, v))
                file_all.write("\n")

                if p_cat != 0 and vuln_count_in_cat[p_cat] > 1:
                    files[p_cat].write("%d " % vuln_id[vuln])
                    for j, v in enumerate(feats):
                        files[p_cat].write("%d:%.3f " % (j+1, v))
                    files[p_cat].write("\n")

            print("%d" % len(packets))


    for f in files: f.close()
    file_all.close()


    
