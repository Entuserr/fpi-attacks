

import csv, sys
from os import listdir
from tools.ngram import updateNGram
from scapy.all import rdpcap
from scapy.all import raw
from os.path import isfile, join, isdir, exists
from preprocess import get_pck_features, get_features_n, get_ngram_size
import xgboost as xgb
from sklearn.externals import joblib
import numpy as np

import ddos

class Classificator:

    def classify_packet(self, p):
        max_score = 0
        max_cat = 0
        data, p_feats = get_pck_features(p)
        feats = p_feats + [0.0] * len(self.chosen_grams)
        
        layer = {}
        updateNGram(layer, data, self.N)

        for k, v in layer.items():
            if k in self.chosen_grams:
                feats[ self.chosen_grams[k] + get_features_n() ] = v

                '''
        result = self.models[0].predict( xgb.DMatrix(np.array([  [0]  + feats ]) ))
        max_cat = np.argmax(result[0])
        #if max_cat != 0:
        #    print (result[0])
        '''
        result = self.model_all.predict( xgb.DMatrix(np.array([  [0]  + feats ]) ))
        v_id = np.argmax(result[0])    

        return (self.vuln_id_cat[v_id], self.vuln_id_global[v_id])

    def classify(self,f, packets):
        c_cnt = {}
        v_cnt = {}
        indices = []
        n = 0
        for p in packets:
            n += 1
            c, vuln = self.classify_packet(p)
            if c > 0:
                indices.append(n)
                c_cnt[c] = c_cnt.get(c,0) + 1
                v_cnt[vuln] = v_cnt.get(vuln,0) + 1

        max_n = 0
        out_category = 0
        for k, v in c_cnt.items():
           # print ("%s - %d" %(k,v))
            if v > max_n:
                out_category = k
                max_n = v

        max_n = 0
        out_vuln = 0
        for k, v in v_cnt.items():
           # print ("%s - %d" %(k,v))    
            if v > max_n:
                out_vuln = k
                max_n = v

        return (f, indices, out_category, out_vuln)

    def __init__(self, folder, N):
        self.N = N
        # gram -> id
        self.chosen_grams = {}  

        # category + vulnerability id -> vulnerability name
        self.vuln_id = {}

        self.vuln_id_global = {}
        self.vuln_id_cat = {}

        cats = [1, 3, 4, 5]
        for c in cats : self.vuln_id[c] = {}

        csv_file = open(join(folder, "grams.csv"), 'r')
        with csv_file:  
            reader = csv.reader(csv_file, delimiter=";")
            for r in reader:
                self.chosen_grams[bytes.fromhex(r[1])] = int(r[0])

        csv_file = open(join(folder, "vulns.csv"), 'r')
        with csv_file:  
            reader = csv.reader(csv_file, delimiter=";")
            for r in reader:
                self.vuln_id[int(r[1])][int(r[2])] = r[0]
                self.vuln_id_global[int(r[3])] = r[0]
                self.vuln_id_cat[int(r[3])] = int(r[1])

        self.vuln_id_global[0] = ""
        self.vuln_id_cat[0] = 0

        self.models = [None] * 6

        #for c in [0, 1, 3, 4]:
        #    print("Loading model %d" % c)
        #    self.models[c] = joblib.load(join(folder, 'model_%d.pkl' % c)) 
        
        self.model_all = joblib.load(join(folder, 'model_all.pkl')) 


if __name__ == "__main__":

    cf = Classificator("./statistics/", get_ngram_size())

    input_dir = "../data/Attacks_test/"
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

    results = []
    for f in files:
        print("Processing : %s.. " % f, end = "")

        packets = rdpcap(join(input_dir, f))
        #shark = pyshark.FileCapture(join(input_dir, f))
        ddos_result = ddos.perform(packets, None)
        if ddos_result[0] > 0.5:
            results.append( (f, ddos_result[1], ddos_result[2], ddos_result[3]) )
        result = cf.classify(f, packets)
        results.append(result)
        #print("%d - %s" % (result[2], result[3]))

    csv_file = open(output_file, 'w', newline = "")  
    with csv_file:  
        writer = csv.writer(csv_file, delimiter=';')
        writer.writerows(results)