
import csv
from math import sqrt, erf, log2
from os.path import exists


def updateNGram(layer, data, N):
    for si in range(0, len(data) - N + 1):
        k = data[si:si+N]
        layer[k] = layer.get(k, 0) + 1


def updateNGramCnt(layer, data, N, cnt_layer):
    for si in range(0, len(data) - N + 1):
        k = data[si:si+N]
        layer[k] = layer.get(k, 0) + 1
        cnt_layer[k] = 1


class NGram:

    def get_best_grams(self, tag, from_tags, n):
        grams = []
        summ = self.g_summ[tag]
        cnt_ex = self.g_cnt_ex[tag]
        cnt = self.g_cnt[tag]
        for k, v in summ.items():
            v_from = 0
            for t in from_tags:
                v2 = self.g_summ[t].get(k, 0)
                v_from += v2
            k1 = v / (v_from + v)
            k2 = cnt_ex[k] / cnt
            grams.append(  ( k, k1 * k2 , v, k1, k2) )
        grams = sorted(grams, key = lambda x : -x[1])
        sq = 0
        lg = (0, 0, 0, 0, 0)
        best_grams = []
        for g in grams:
            if g[3] != lg[3] or g[4] != lg[4]:
                sq = 0
            else:
                sq += 1
            lg = g
            if sq < 2:
                best_grams.append(g)

        return best_grams[0:min(n, len(grams))]


    def do_zero_class(self):
        summ = {}
        self.g_summ["zero"] = summ
        self.g_cnt["zero"] = len(self.zero_class)
        for data in self.zero_class:
            updateNGram(summ, data, self.N)
        self.zero_class = None


    def append(self, data, tag):
        if tag is None:
            self.zero_class.append(data)
        else:
            summ = self.g_summ.get(tag)
            cnt = self.g_cnt.get(tag)
            cnt_ex = self.g_cnt_ex.get(tag)
            if summ is None:
                summ = {}
                cnt = 0
                cnt_ex = {}
                self.g_summ[tag] = summ
                self.g_cnt[tag] = 0
                self.g_cnt_ex[tag] = cnt_ex
            cnt_layer = {}
            updateNGramCnt(summ, data, self.N, cnt_layer)
            for k in cnt_layer.keys():
                cnt_ex[k] = cnt_ex.get(k, 0) + 1
            self.g_cnt[tag] = cnt + 1
        

    def __init__(self, N):
        self.N = N
        self.layers = {}
        self.zero_class = []
        self.epoch = 0

        self.g_summ  = {}
        self.g_cnt   = {}
        self.g_cnt_ex ={}