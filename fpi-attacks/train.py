
import csv, sys
from os import listdir, makedirs
from os.path import isfile, join, isdir, exists
from tools.ngram import NGram, updateNGram
import xgboost as xgb
from sklearn.externals import joblib

if __name__ == "__main__":

    input_dir = "./statistics/"

    if len(sys.argv) > 1:
        input_dir = sys.argv[1]

    # gram -> id
    chosen_grams = {}  

    # category + vulnerability id -> vulnerability name
    vuln_id = {}

    vuln_id_global = {}

    cats = [1, 3, 4, 5]
    for c in cats : vuln_id[c] = {}

    csv_file = open(join(input_dir, "grams.csv"), 'r')
    with csv_file:  
        reader = csv.reader(csv_file, delimiter=";")
        for r in reader:
            chosen_grams[bytes.fromhex(r[1])] = int(r[0])

    csv_file = open(join(input_dir, "vulns.csv"), 'r')
    with csv_file:  
        reader = csv.reader(csv_file, delimiter=";")
        for r in reader:
            vuln_id[int(r[1])][int(r[2])] = r[0]
            vuln_id_global[int(r[3])] = r[0]

    vuln_id_global[""] = 0
    '''
    for c in [0, 1, 3, 4]:
        print("Training category %d" % c)
        dtrain = xgb.DMatrix(join(input_dir, 'train_%d.txt' % c))

        if c == 0:
            param = {
                'max_depth': 11,  # the maximum depth of each tree
                'eta': 0.3,  # the training step for each iteration
                'objective': 'multi:softprob'}  # error evaluation for multiclass training
            num_round = 50  # the number of training iterations
        else:
            param = {
                'max_depth': 4,  # the maximum depth of each tree
                'eta': 0.3,  # the training step for each iteration
                'objective': 'multi:softprob'}  # error evaluation for multiclass training
            num_round = 20  # the number of training iterations

        if c == 0:
            param['num_class'] = 6
        else:
            param['num_class'] = len(vuln_id[c])

        bst = xgb.train(param, dtrain, num_round)
        bst.dump_model(join(input_dir, 'model_%d.txt' % c))
        joblib.dump(bst, join(input_dir, 'model_%d.pkl' % c), compress=True)
    '''
    print("Training category - all")

    param = {
        'max_depth': 7,  # the maximum depth of each tree
        'eta': 0.2,  # the training step for each iteration
        'objective': 'multi:softprob',
        'max_delta_step' : 1,
        'min_child_weight' : 1,
        'scale_pos_weight' : 1,
        'verbosity' : 1 }  # error evaluation for multiclass training
    num_round = 75  # the number of training iterations
    param['num_class'] = len(vuln_id_global)

    dtrain = xgb.DMatrix(join(input_dir, 'train_all.txt'))
    bst = xgb.train(param, dtrain, num_round, verbose_eval = True)
    bst.dump_model(join(input_dir, 'model_all.txt'))
    joblib.dump(bst, join(input_dir, 'model_all.pkl'), compress=True)