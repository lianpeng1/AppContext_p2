import networkx as nx
import codecs

def getMethodFromLabel(label):
    label = label.replace('/',' ')
    label = label.replace('(',' ')
    label = label.replace(')',' ')
    label = label.replace('<',' ')
    label = label.replace('>',' ')
    words = label.split()
    for i,word in enumerate(words):
        if ';-' in word:
            words[i] = words[i].replace(';-',' ')
            words[i] = words[i].split()[0]
            string = words[i]+'.'+words[i+1]
            break
    return string

def getEntrypoint(sensitive_method, method_list, entrypoint, edge_source, edge_target):
    for ix, method in enumerate(method_list):
        if sensitive_method in method:
            tmp = entrypoint[ix]
            tmp_ix = ix
            while tmp == '0':
                tmp_ix = edge_target.index(str(tmp_ix)) if (str(tmp_ix) in edge_target) else -1
                tmp_ix = edge_source[tmp_ix]
                tmp = entrypoint[int(tmp_ix)]
            return method_list[int(tmp_ix)]



path = ("tool/callgraph.gml")

G = nx.read_gml(path)
entrypoint=[]
label=[]
method=[]

edge_source=[]
edge_target=[]

for id, string in enumerate(G.nodes()):
    label.append(string)

for i, x in enumerate(label):
    method.append(getMethodFromLabel(label[i]))

fo = codecs.open(path, 'r', 'utf-8')
for line in fo.readlines():
    if "entrypoint" in line.split():
        entrypoint.append(line.split()[1])
    if "source" in line.split():
        edge_source.append(line.split()[1])
    if "target" in line.split():
        edge_target.append(line.split()[1])
fo.close()

# sensitive_method_name = 'sendTextMessage'
# for ix, fake in enumerate(method):
#     if sensitive_method_name in fake.split('.'):
#         tmp = entrypoint[ix]
#         tmp_ix = ix
#         if tmp == '0':
#             print(str(tmp_ix))
#             print(tmp)
#             tmp_ix = edge_target.index(str(tmp_ix)) if (str(tmp_ix) in edge_target) else -1
#             tmp_ix = edge_source[tmp_ix]
#             print(entrypoint[int(tmp_ix)])

path = "test/output1.csv"
fw = codecs.open(path, 'w', 'utf-8')
fw.write("sensitive_method_name,entry_point\n")

sensitive_method_name=[]
sensitive_method_name.append('SmsManager.sendTextMessage')
sensitive_method_name.append('Service.onStart')


for method_name in sensitive_method_name:
    
    entry_point_name = getEntrypoint(method_name, method, entrypoint, edge_source, edge_target)
    fw.write("".join([method_name, ",", entry_point_name,  "\n"]))

fw.close()