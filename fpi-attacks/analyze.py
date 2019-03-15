import csv, sys, pyshark, time
from os import listdir
from os.path import isfile, join, isdir

from scapy.all import rdpcap
import ddos, overflow, bruteforce

# usage : analyze.py [input pcap or directory] [output file]

def analyze(fname, packets, shark):
    #score, packet list, class, vulnerability
    result = (0.0, [], 0, "none")

    
    analyzers = [ddos.perform, bruteforce.perform, overflow.perform]

    times = [0.0] * len(analyzers)

    for i, f in enumerate(analyzers):
        start_time = time.perf_counter()
        attempt = f(packets, shark)
        if attempt is not None and attempt[0] > result[0]:
            result = attempt 
        times[i] = time.perf_counter() - start_time
        #print("%.2f s " % times[i], end = "", flush = True)
        if result[0] > 0.5:
            break

        

    packet_list = "[" + ",".join(str(i) for i in result[1]) + "]"
    return ( fname,packet_list, result[2], result[3] )

class DevNull:
    def write(self, msg):
        pass

if __name__ == "__main__":

    input_dir = "../data/Attacks_train/"
    output_file = "./output.csv"

    if len(sys.argv) > 1:
        input_dir = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    if isdir(input_dir):
        files = [f for f in listdir(input_dir) if isfile(join(input_dir, f)) and f.endswith(".pcap") ]
    elif isfile(input_dir):
        files = [input_dir]
        input_dir = "./"
    else:
        print("File %s not found" % input_dir)
        sys.exit(-1)

    if len(files) == 0:
        print("No .pcap files found")
        sys.exit(0)

    print("Loading models...")
    overflow.init("./statistics/")
    sys.stderr = DevNull()

    results = []

    time_batch_start = time.perf_counter()

    tot_packets = 0
    
    for i, f in enumerate(files):
        #print("Processing : %s.. " % f, end = "")
        time_start = time.perf_counter()
        print("File %s (%d/%d).. " % (f, i+1, len(files)), end="", flush=True)
        packets = rdpcap(join(input_dir, f))
        shark = pyshark.FileCapture(join(input_dir, f))
        result = analyze(f, packets, shark)
        results.append(result)
        time_end = time.perf_counter()
        tot_packets += len(packets)
        #print("completed in %.3f seconds, %s" % (time_end - time_start, result[3]), flush=True)
        if i > 1:
            remains = (time_end - time_batch_start) * (len(files) - (i + 1)) / (i + 1)
            print("completed in %.2f s. %d packets processed,  %.2f s total, ~%.1f s remaining" %
                (time_end - time_start, tot_packets, time_end - time_batch_start, remains), flush=True)
        else:
            print("completed in %.2f s. %d packets processed,  %.2f s total" %
                (time_end - time_start, tot_packets, time_end - time_batch_start), flush=True)
        #print("%d - %s, %.3f seconds" % (result[2], result[3], time_end - time_start))

    time_end = time.perf_counter()
    print("Analysis complete, %.3f seconds elapsed" % (time_end - time_batch_start))

    csv_file = open(output_file, 'w', newline = "")  
    with csv_file:  
        writer = csv.writer(csv_file, delimiter=';')
        writer.writerow(["pcap_name","packets","attack_class","vulnerability"])
        writer.writerows(results)
