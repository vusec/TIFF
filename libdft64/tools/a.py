import json
import collections
import os

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
"""
for k,val in data.items():
   for v in val:
     s = int(k)
     e = int(k) + int(diff[str(v[0])]) - 1
     if (s,e) in m.keys():
       m[(s,e)] += 1
     else:
       m[(s,e)] = 1
"""
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
"""
f = open('file.taint', "r")
d = f.readlines()
for line in d:
  l = line.strip().split(":")
 # print l[0]
  if int(l[0]) in final_write.keys():
    continue
  else:
    size = int(l[1])
    fl = 1
    for i in range(0,sz):
      if int(l[0]) + i in final_write.keys():
        fl = 0
        break
    if fl == 1:
     final_write[int(l[0])] = reverse_diff[int(l[1])]
f.close()
od = collections.OrderedDict(sorted(final_write.items()))
print len(od.keys())
#for k,v in od.items():
#  print k,":",reverse_diff[v]
"""
with open('err_offset.json', 'w') as fp:
	json.dump(od, fp)

od = collections.OrderedDict({})
with open('err_arr_offset.json', 'w') as fp:
        json.dump(od, fp)



with open('err_offset.json', 'w') as fp:
        json.dump(final_offset, fp)
