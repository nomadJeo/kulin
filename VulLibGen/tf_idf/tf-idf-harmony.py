import os, sys
os.environ["CUDA_VISIBLE_DEVICES"] = "4"  
import json
import re
import time
import pandas as pd
from multiprocessing import Pool
from tqdm import tqdm
import tfidf_searching
from clean_text import cleaned_text

import importlib
importlib.reload(tfidf_searching)

with open('/nvme2n1/YangYJworks/@VulApiAlarm/VulLibMiner/myData/RQ3harmony/train_1668.json', 'r') as f:
    trains = json.load(f)
with open('/nvme2n1/YangYJworks/@VulApiAlarm/VulLibMiner/myData/RQ3harmony/test.json', 'r') as f:
    tests = json.load(f)

oskg_folder = '/nvme2n1/YangYJworks/@VulApiAlarm/VulLibMiner/myData/RQ3harmony/'
# node_path = os.path.join(oskg_folder, 'oskg_node2os_20231120163318.csv')
# edge_path = os.path.join(oskg_folder, 'oskg_edges_20231120163318.csv')
pros_path = os.path.join(oskg_folder, 'label_desc_combine.csv')

# nodes = pd.read_csv(node_path, delimiter='\t', header=None)
# edges = pd.read_csv(edge_path, delimiter='\t', header=None)
pros = pd.read_csv(pros_path)

#获得names列表
pros = pros[pros.apply(lambda x: type(x['name']) == str, axis=1)]
pros_names = set([name.lower() for name in pros.name.to_list() if type(name) == str])

def get_c_artifact(lib):
    complete_name = ':'.join(lib.split(':')[1:])  # 取第二部分及之后部分
    artifact = complete_name.split('/')[-1]      # 取最后一部分
    artifact = artifact.split(':')[0]            # 去掉版本号
    return artifact.lower()

vulns = trains + tests
# vuln_labels = [get_c_artifact(vuln['label']) for vuln in vulns]
vuln_labels = [  
    get_c_artifact(label)   
    for vuln in vulns   
    for label in vuln['labels']  # 先提取每个 cve 的 labels，然后处理  
]
# 训练集总标签数

train_label_count2 = sum(len(v["labels"]) for v in trains)
test_label_count = sum(len(v["labels"]) for v in tests)
train_label_count = len(vuln_labels) - test_label_count

name_weight = 4
pros_corpus = pros.drop_duplicates('name')[['name', 'summary']]
pros_corpus.columns = ['object', 'token']
pros_corpus.object = pros_corpus.object.apply(lambda x: x.lower())
pros_corpus.token = pros_corpus.token.apply(lambda x: x if type(x) == str else ' ')
pros_mapping = pros_corpus.set_index('object').to_dict()
pros_corpus.token = pros_corpus.apply(\
                    lambda x: f"{x['object'] * name_weight} {x['token']}", axis=1)

pros_corpus.token = pros_corpus.token.apply(lambda x: cleaned_text(x))
pros_corpus.token = pros_corpus.token.apply(lambda x: ' '.join(x))

print('pros_corpus len: ', len(pros_corpus))
print('len(vuln_labels) len: ', len(vuln_labels))
print('train_label_count: ', train_label_count)
print('train_label_count2: ', train_label_count2)
print('test_label_count: ', test_label_count)

search_engine = tfidf_searching.TfidfSearching(pros_corpus, 512, 2)

def recall(vuln, search_result, k=128):
    artifact = get_c_artifact(vuln['raw_label'])
    return artifact in search_result[:k]

def fun(vuln):
    search_engine = tfidf_searching.TfidfSearching(pros_corpus, 1024, 2)
    return search_engine.search_topk_objects(cleaned_text(vuln['desc']), [])

with Pool(processes=16) as pool:
    tf_idf_res = list(tqdm(pool.imap(fun, vulns), total=len(vulns)))
    # tf_idf_res = list(tqdm(pool.imap(fun, vulns)))

for vuln, res in zip(vulns, tf_idf_res):
    vuln['top_k'] = [{'lib_name': lib, 'website_description':\
                      pros_mapping['token'][lib]} for lib in res]
    vuln['raw_label'] = vuln['labels']
    vuln['labels'] = [get_c_artifact(label) for label in vuln['labels']]
    # del vuln['label']

output_dir = '/nvme2n1/YangYJworks/@VulApiAlarm/VulLibMiner/myData/RQ3harmony/output_1668/'
train_path = os.path.join(output_dir, 'train.json')
valid_path = os.path.join(output_dir, 'valid.json')
test_path = os.path.join(output_dir, 'test.json')



# new_train = [vuln for vuln, label in zip(trains, vuln_labels[:-5103]) if label in pros_names]
# new_test = [vuln for vuln, label in zip(tests, vuln_labels[-5103:]) if label in pros_names]
new_train = [
    vuln for vuln, label in zip(trains, vuln_labels[:train_label_count])
]
new_test = [
    vuln for vuln, label in zip(tests, vuln_labels[train_label_count:])
]


with open(train_path, 'w') as f:
    json.dump(new_train, f)

with open(valid_path, 'w') as f:
    json.dump(new_test, f)

with open(test_path, 'w') as f:
    json.dump(new_test, f)

print('已将结果输出至output')