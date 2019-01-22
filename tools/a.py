import json
import collections
import os

with open('temp_final_offset.json', 'r') as fp:
       data = json.load(fp)

diff = {'INT8':1,'INT16':2,'INT32':4,'INT64':8,'INT128':16}
reverse_diff = {1:'INT8',2:'INT16',4:'INT32',8:'INT64',16:'INT128'}

m = {}
f = open('file.taint', "r")
d = f.readlines()
for line in d:
  l = line.split(":")
  s = int(l[0].split(",")[0])
  e = s + int(l[0].split(",")[1]) - 1;
  if (s,e) in m.keys():
    m[(s,e)] += int(l[1])
  else:
    m[(s,e)] = int(l[1])
#print m

od = sorted(m.keys(), key=lambda x: (x[0], -x[1]))
#print od
final = {}
for k in od:
  if k[0] in final.keys():
    final[k[0]].append([k,m[k]])
  else:
    final[k[0]] = [[k, m[k]]]
temp = {}
for k,v1 in final.items():
  ma = -1
  maval = []
  for v in v1:
    if ma < v[1]:
      ma = v[1]
      maval = v
  temp[k] = maval
od = collections.OrderedDict(sorted(temp.items()))
g = sorted(od.keys(), key=lambda k: od[k][1], reverse=True)
final_write = {}
for k in g:
  if k in od.keys():
    sz = od[k][0][1] - od[k][0][0]  + 1
    final_write[k] = sz
    for i in range(0, sz):
      if k+i in od.keys():
        od.pop(k+i, None)
final_offset = collections.OrderedDict(sorted(final_write.items()))
#print final_write.keys()

with open('err_offset.json', 'w') as fp:
	json.dump(od, fp)

with open('final_array.json', 'r') as fp:
       data = json.load(fp)

m = {}
for k,val in data.items():
  for v in val:
    s = int(k)
    e = int(v[0][-1])
    far = v[1][-1]
    if s in m.keys():
       m[s].append((e,v[1],far))
    else:
       m[s] = [(e,v[1],far)]
    for off in v[0]:
      if off in final_offset.keys() and diff[v[1][0]] == final_offset[off]:
        final_offset.pop(off, None)
od = collections.OrderedDict(sorted(m.items()))
#print od
ma = {}
max_so_far = -1
makey = -1
final_array = {}
for k,val in od.items():
  for v in val:
    if k < max_so_far:
      if v[0] < max_so_far:
        final_array[makey].append([k, v[0], v[1], v[2]])
      else:
        if k in final_array.keys():
          final_array[k].append([k,v[0],v[1], v[2]])
          ma[k] = max(v[0], ma[k])
        else:
          final_array[k] = [[k,v[0],v[1], v[2]]]
          ma[k] = v[0]
        makey = k
        max_so_far = v[0]
      continue
    if k in final_array.keys():
      final_array[k].append([k, v[0], v[1], v[2]])
      ma[k] = max(v[0], ma[k])
    else:
      final_array[k] = [[k, v[0], v[1],v[2]]]
      ma[k] = v[0]
    if max_so_far < v[0]:
      max_so_far = v[0]
      makey = k
od = collections.OrderedDict(sorted(final_array.items()))
s = {}
for k,val in od.items():
  for v in val:
    if k in s.keys():
      s[k].add((v[0], v[1], diff[v[2][0]], v[3]))
    else:
      s[k] = set()
      s[k].add((v[0], v[1], diff[v[2][0]], v[3]))
  s[k] = list(s[k])
od = collections.OrderedDict(sorted(s.items()))

with open('err_arr_offset.json', 'w') as fp:
        json.dump(od, fp)



with open('err_offset.json', 'w') as fp:
        json.dump(final_offset, fp)
