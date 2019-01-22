import os
import json

hash_offset = {'INT8':0, 'INT16':1,'INT32':3,'INT64':7,'INT128':15, 'VOID*':7}
diff_map = {'INT8':1,'INT16':2,'INT32':4,'INT64':8, 'INT128':16}

def get_malloc_reward_arr(type_offset):
  return_vals = []
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      function = types[0]
      if data_type == "int":
        ans = types[2].split(":")
        ans = [x[1:-1].split(",") for x in ans]
        final_result = []
        for i in ans:
            for j in i:
                if j != "":
                    final_result.append(int(j))
        final_result.sort()
        i = 0
        j = 0
        k =final_result[i]
        #print final_result
        i =0
        j=1
        while 1:
            if i==len(final_result) or j >= len(final_result):
                break
            else:
                while j<len(final_result) and final_result[j] == final_result[j-1]+1:
                    j = j+1
		if j-i > 4:
                  return_vals.append([final_result[i], 4])
                  return_vals.append([final_result[i+4], j-(i+4)])
		else:
                  return_vals.append([final_result[i], j-i])
                i=j
                j=i+1
  return_vals.sort(key=lambda x: int(x[0]))
  final_return = {}
  for i in return_vals:
    if i[0] not in final_return.keys():
      final_return[i[0]] = i[1]
    else:
      final_return[i[0]] = max(final_return[i[0]],i[1])
  return_vals = []
  for key,value in final_return.iteritems():
     if value == type_offset:
       return_vals.append(key)
  return_vals.sort()
  #print final_return
  return return_vals


def get_offset(type_offset):
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'err_offset.json')) as data_file:    
    data = json.load(data_file)
  reward_off = get_malloc_reward_arr(type_offset);
  return_vals = []
  for key,value in data.items():
    if int(value) == int(type_offset):
      return_vals.append(key)
  for i in reward_off:
    if i not in return_vals:
      return_vals.append(i)
  return_vals.sort(key=int)
  return return_vals

def get_all_offsets():
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'err_offset.json')) as data_file:
    data = json.load(data_file)
  return_vals = {}
  for key,value in data.items():
    return_vals[int(key)] = int(value)
  return return_vals

def get_arrays():
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'err_arr_offset.json')) as data_file:    
    data = json.load(data_file)
  return_vals = []
  for key,value in data.items():
    for v in value:
      return_vals.append([int(v[0]),int(v[1]),int(v[2]), int(v[3])])
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      if data_type == "char*":
        return_vals.append([int(types[2]), int(types[3])+int(types[2]), int(1), -1])
  return_vals.sort(key=lambda x: int(x[0]))
  return return_vals

"""
def get_special():
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'temp_final_offset.json')) as data_file:
    off_data = json.load(data_file)
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'final_array.json')) as data_file:
    arr_data = json.load(data_file)
  return_vals = []
  for key in arr_data.keys():
    diff = [1,2,4,8]
    values_arr = arr_data[key][0][1]
    for v in diff:
      updated_key = str(int(key)-v)
      if updated_key in off_data.keys():
        values_offset = off_data[updated_key]
	for val in values_offset:
	  if val[2] == values_arr[2] and v == diff_map[val[0]]:
	    return_vals.append([(key,len(arr_data[key][0])), updated_key, val[0]])
  return_vals.sort(key=lambda x: int(x[1]))
  return return_vals
"""

def get_reward_arr():
  return_vals = []
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      if data_type == "char*":
        return_vals.append([int(types[2]), int(types[3])])
  return_vals.sort(key=lambda x: int(x[0]))
  return return_vals

def get_memchr_reward_arr():
  return_vals = []
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      function = types[0]
      if data_type == "char*" and (function == "memchr" or function=="rawmemchr"):
        return_vals.append([int(types[2]), int(types[3]), int(types[4])])
  return_vals.sort(key=lambda x: int(x[0]))
  return return_vals



def get_cmp_reward_arr():
  return_vals = {}
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      function = types[0]
      if data_type == "char*" and (function == "strcmp" or function=="memcmp" or function=="strncmp"):
	if int(types[2]) in return_vals:
          return_vals[int(types[2])].append([int(types[3]), format(types[4]).decode('hex')])
	else:
          return_vals[int(types[2])] = [[int(types[3]), format(types[4]).decode('hex')]]
  for k,v in return_vals.iteritems():
    return_vals[k] = sorted(return_vals[k], key=lambda x: int(x[0]))
  #return_vals.sort(key=lambda x: int(x[0]))
  return return_vals

def get_prone_arr():
  return_vals = []
  dir_path = os.path.dirname(os.path.realpath(__file__))
  with open(os.path.join(dir_path, 'reward.taint')) as data_file:
    for line in data_file:
      types = line.strip().split()
      data_type = types[1]
      function = types[0]
      if data_type == "char*" and (function == "strcmp" or function=="strcpy" or function=="strlen"):
	  return_vals.append([int(types[2]), int(types[3])])
  return_vals.sort(key=lambda x: int(x[0]))
  return return_vals 
 
if __name__ == "__main__":
  print "INT8 = ",get_offset("1")
  print "INT16 = ",get_offset("2")
  print "INT32 = ",get_offset("4")
  print "INT64 = ",get_offset("8")
  print "arrays = ",len(get_arrays())
  #print "special = ",get_special()
  #print "mallic = ",get_malloc_reward_arr()
  #print "rewards_arrays = ",get_reward_arr()
