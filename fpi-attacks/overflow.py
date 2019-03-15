
import tools.ngram

from classify import Classificator
from os.path import join, exists
from preprocess import get_ngram_size

classificator = None

def init(folder):
    global classificator
    if exists(join(folder, "model_all.pkl")):
        classificator = Classificator(folder, get_ngram_size())
    else:
        print("Warning : model file not found (some classification won't be working)")

def perform(packets, shark):
    global classificator
    if classificator is None:
        return (0.0, [], 3, "Common buffer overflow")

    result = classificator.classify("", packets)
    if result[2] != 0:
        return (1.0, result[1], result[2], result[3])
    else:
        return (0.0, [], 0, "")


    