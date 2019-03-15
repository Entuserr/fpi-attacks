import csv


def check(train,output):
    train_csv = list(csv.DictReader(train,delimiter = ';'))
    output_csv = list(csv.DictReader(output,delimiter = ';'))
    i = 0
    errors = []
    for train_line in train_csv:
        for output_line in output_csv:
            if output_line['pcap_name'] == train_line['pcap_name']:
                if (output_line['packets'] == train_line['packets']):
                    i += 1
                else:
                    print(output_line['pcap_name'],':')
                    print('output',output_line['packets'])
                    print('train',train_line['packets'])
                    errors.append(output_line['pcap_name'])
    print(i)
    print(errors)

train = open('../data/attacks_train.csv','r')
output = open('output.csv', 'r')
check(train,output)