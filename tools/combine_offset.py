import os, sys
import json
import pprint
import collections
from shutil import copyfile

type_map = {-1:'VOID*',0:'INT8',1:'INT16',2:'INT32',3:'INT64',4:'INT128'}
remove_map = {'INT8':0, 'INT16':1,'INT32':3,'INT64':7,'INT128':15, 'VOID*':7}
def main():
  final_map = {}
  temp_final_map = {}
  arr_map = {}
  dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "howard")
  f = open(os.path.join(dir_path, 'pid'), 'r')
  pid = f.readlines()[0].strip()
  #print pid
  top_dir = os.path.join(dir_path, str(pid))
  id_struct = 1
  for root, d, files in os.walk(top_dir):
    if root == top_dir:
      copyfile(os.path.join(top_dir, 'reward.taint'), 'reward.taint')
      copyfile(os.path.join(top_dir, 'file.taint'), 'file.taint')
      f = open(os.path.join(top_dir, 'file.taint'), "r")
      d = f.readlines()
      """
      for line in d:
        l = line.strip().split(":")
        final_map[int(l[0].split(",")[0])] = [type_map[int(l[1])], 0, 0]
      """
      f.close()
      os.system("python get_ds.py --taint %s --array %s --isheap y --id %d"%(os.path.join(top_dir, 'heap.taint'), os.path.join(top_dir, 'heap_array.raw'), id_struct))
      with open('file_offset.json') as json_data:
        d = json.load(json_data)
      for k,v in d.items():
        ma = -2
        #print final_map,k,v
        if int(k) in final_map.keys():
	  maval = []
          for val in v:
            if ma < int(remove_map[val[0]]):
              ma = int(remove_map[val[0]])
	      maval = val
          if ma > remove_map[final_map[int(k)][0]]:
              final_map[int(k)] = maval
	else:
	  maval = []
          for val in v:
            if ma < int(remove_map[val[0]]):
              ma = int(remove_map[val[0]])
	      maval = val
          final_map[int(k)] = maval
      for k,v in d.items():
	if int(k) in temp_final_map.keys():
	  temp_final_map[int(k)].extend(v)
	else:
	  temp_final_map[int(k)] = v
      #print "heap"
      with open('arr_offset.json') as json_data:
        data = json.load(json_data)
    #  print data
      for k,v in data.items():
        if k in arr_map.keys():
            arr_map[k].extend(v)
        else:
          arr_map[k] = v
      continue
    else:
      #print root
      f = open("id_struct", "r");
      d = f.readlines();
      f.close();
      if os.path.exists(os.path.join(root, "stack_taint.raw")):
        os.system("python get_ds.py --taint %s/stack_taint.raw --array %s/stack_array.raw --isheap n --id %d"%(root, root, int(d[0].strip("\n"))))
      else:
	continue
      with open('file_offset.json') as json_data:
        d = json.load(json_data)
      for k,v in d.items():
        ma = -2
        #print final_map,k,v
        if int(k) in final_map.keys():
          maval = []
          for val in v:
            if ma < int(remove_map[val[0]]):
              ma = int(remove_map[val[0]])
              maval = val
          if ma > remove_map[final_map[int(k)][0]]:
              final_map[int(k)] = maval
        else:
          maval = []
          for val in v:
            if ma < int(remove_map[val[0]]):
              ma = int(remove_map[val[0]])
              maval = val
          final_map[int(k)] = maval
      """
      for k,v in d.items():
        id_struct = max(id_struct, v[2])
        ma = -2
        if int(k) in final_map.keys():
          if ma < final_map[int(k)][0]:
            ma = final_map[int(k)][0]
            final_map[int(k)] = v
        if ma < int(v[0]):
          ma = int(v[0])
          final_map[int(k)] = v
          ma = max(ma, final_map[int(k)])
      """
      for k,v in d.items():
	if int(k) in temp_final_map.keys():
	  temp_final_map[int(k)].extend(v)
	else:
	  temp_final_map[int(k)] = v
      with open('arr_offset.json') as json_data:
        data = json.load(json_data)
     # print data
      od1 = collections.OrderedDict(sorted(temp_final_map.items()))
      #print d,od1,root
      for k,v in data.items():
        if k in arr_map.keys():
	#          if len(arr_map[k]) < len(v[0]):
       #     print k,v,arr_map[k]
          arr_map[k].extend(v)
        else:
          arr_map[k] = v
  temp_map = final_map.copy()
#  print temp_map
  """
  for k in sorted(temp_map.keys()):
    print k,temp_map[k][0]
  """
  for key,values in arr_map.items():
    for a in range(0, len(values)):
        for v in values[a][0]:
          if int(v) in final_map.keys():
            final_map.pop(int(v), None)
	  #temp_final_map.pop(int(v), None)
  temp_map = final_map.copy()
  for k in sorted(final_map.keys()):
    #print k,final_map[k]
    for i in range(0,remove_map[final_map[k][0]]):
      temp_map.pop(k+i+1, None)
  temp_map = {int(k):v for k,v in temp_map.items()}
  temp_final_map = {int(k):v for k,v in temp_final_map.items()}
  od = collections.OrderedDict(sorted(temp_map.items()))
  with open('final_offset.json', 'w') as f:
    json.dump(od, f)
  od1 = collections.OrderedDict(sorted(temp_final_map.items()))
  #print od1
  with open('temp_final_offset.json','w') as f:
    json.dump(od1, f)
  arr_map = {int(k):v for k,v in arr_map.items()}
  od = collections.OrderedDict(sorted(arr_map.items()))
  with open('final_array.json', 'w') as f:
    json.dump(od, f)
  """
  #print arr_map
  pp = pprint.PrettyPrinter(indent = 1)
  with open('final_offset.json') as f:
    data = json.load(f)
  pp.pprint(data)
  with open('final_array.json') as f:
    data = json.load(f)
  pp.pprint(data)
  for k in sorted(arr_map.keys()):
    print arr_map[k]
  """
if __name__ == '__main__':
  main()
