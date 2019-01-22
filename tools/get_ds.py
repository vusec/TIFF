import os, sys
import argparse
import json


file_map = {}
temp_file_map = {}
remove_addr = []
type_map = {'VOID*':-1,'INT8':0,'INT16':1,'INT32':2,'INT64':3,'INT128':4}
diff = {'INT8':1,'INT16':2,'INT32':4,'INT64':8,'INT128':16}
reverse_diff = {1:'INT8',2:'INT16',4:'INT32',8:'INT64',16:'INT128'}
id_struct = 0
def gcd(a, b):
	if a < b:
		a, b = b, a

	while b != 0:
		temp = a % b
		a = b
		b = temp
	return a

class TAG:
	def __init__(self):
		self.addr = 0;
		self.base = 0;
		self.size = 0;
		self.size_file = 0;
		self.file_taint = "";
		self.isArray = False;
		self.isPointer = False;
		self.childs = set();
		return;

	def set_flag(self, flag):
		self.isArray = False;
		self.isPointer = False;
		if (flag & 0x10 == 0x10):
			self.isArray = True;
		if (flag & 0x1 == 0x1):
			self.isPointer = True;

	def load_from_line(self, l):
		parts = l.split(",");
		self.addr = int(parts[0].split(":")[0],16);
		self.base = int(parts[0].split(":")[1],16);
		self.size = int(parts[1].split("size=")[1],16);
		flag = int(parts[2].split("flag=")[1],16);
		self.size_file = int(parts[3].split("size_file=")[1],16);
		self.file_taint = ",".join(parts[4:]).split("file=")[1].strip()
		self.childs = set();
		self.set_flag(flag);
		return;
	
	def get_struct_size(self):
		highest = self.addr + self.size;
		for child in self.childs:
			child_size = child.get_struct_size();
			if child_size > highest:
				highest = child_size;
		return highest;

def get_type(size):
#	if tag.isPointer:
#		return "VOID*";
#	else:
	return "INT%d"%(size*8);
	
def get_offsets(tag, addr, tagmap, off_map):
	f_taint = tag.file_taint.split(":")
	result = []
	for taint in range(0,1):
  	  offsets = off_map[addr]
	  size = tag.size
	  end_addr = addr+size-1;
	  if end_addr in off_map.keys():
		for off in offsets:
			isPos = 1
			breakval = -1
			mi = off
			for i in range(0,size):
				if addr+i in off_map.keys() and len(off_map[addr+i]) > taint and int(off+i) in off_map[addr+i]:
					continue;
				elif addr+i in off_map.keys() and len(off_map[addr+i]) > taint and int(off-i) in off_map[addr+i]:
					mi = min(int(off-i),mi)
					continue
				else:
					breakval = i
					isPos = 0;
					break
			if isPos == 1:
				result.append([int(mi),size])
			elif isPos == 0:
				if breakval == 0 or breakval == 1:
				  result.append([int(mi),1])
				elif breakval == 2 or breakval == 3:
				  result.append([int(mi),2])
				elif breakval == 4 or breakval == 5 or breakval == 6 or breakval == 7:
				  result.append([int(mi),4])
				else:
				  result.append([int(mi),8])
	  else:
		for off in offsets:
			isPos = 1
			breakval = -1
			mi = off
			for i in range(0,size):
				if addr+i in off_map.keys() and len(off_map[addr+i]) > taint and int(off+i) in off_map[addr+i]:
					continue;
				elif addr+i in off_map.keys() and len(off_map[addr+i]) > taint and int(off-i) in off_map[addr+i]:
                                        mi = min(int(off-i),mi)
                                        continue

				else:
					breakval = i
					isPos = 0;
					break
			if isPos == 1:
				result.append([int(off),size])
			elif isPos == 0:
				if breakval == 0 or breakval == 1:
				  result.append([int(mi),1])
				elif breakval == 2 or breakval == 3: 
				  result.append([int(mi),2])
				elif breakval == 4 or breakval == 5 or breakval == 6 or breakval == 7:
				  result.append([int(mi),4])
				else:
				  result.append([int(mi),8])
	
	return result

def process_tagmap(tagmap, root, stack_taint):
	sorted_addr = sorted(tagmap.keys());
#Detect loops, and use the lower one
	for addr in sorted_addr:
		base_addr = tagmap[addr].base;
		accessed  = set();
		accessed.add(addr);
		while (base_addr != root)and(base_addr not in accessed):
			accessed.add(base_addr);
			base_addr = tagmap[base_addr].base;
		if (base_addr != root):
			base_addr = sorted(accessed)[0];
			tagmap[base_addr].base = root;
#Detect base above child
	for addr in sorted_addr:
		base_addr = tagmap[addr].base;
		nearest_base = base_addr;
		adjust = False;
		while (base_addr != root)and(base_addr > addr):
			adjust = True;
			nearest_base = base_addr;
			base_addr = tagmap[base_addr].base;
		if (adjust):
			tagmap[addr].base = base_addr;
			tagmap[nearest_base].base = addr;

#Adjust base when crossing
	index = 0;
	while (index < (len(sorted_addr)-1)):
		addr = sorted_addr[index];
		next_index = index+1;
		next_addr = sorted_addr[next_index];
		while (tagmap[next_addr].base < addr):
			if (tagmap[next_addr].base > tagmap[addr].base):
				tagmap[next_addr].base = tagmap[addr].base;
			next_index += 1;
			if (next_index >= len(sorted_addr)):
				break;
			next_addr = sorted_addr[next_index];
		index += 1;
#build childs
	for addr in sorted_addr:
		if (addr != root):
#			print "addr = %x"%(addr)
#			print "base = %x"%(tagmap[addr].base);
			tagmap[tagmap[addr].base].childs.add(addr);
		else:
			tagmap[root].base = root;
	return tagmap;

def get_off(tag, off_map, tagmap):
	addr = tag.addr
	sz = tag.size
	s= ""
	s += tagmap[addr].file_taint
	#for i in range(0,sz):
	#	s += off_map[addr+i]
	return s

def dump_ds(tagmap, base, indent, off_map, isReverse=False, depth=0):
	childs = sorted(tagmap[base].childs, reverse=isReverse);
	for addr in childs:
		offsets = get_offsets(tagmap[addr], addr, tagmap, off_map);
		#print offsets
		r = depth
		if (len(tagmap[addr].childs) != 0):
			if(tagmap[addr].size > 0):
				if depth == 0:
				  global id_struct
				  id_struct = id_struct + 1
				r = r+1;
		global file_map
		global temp_file_map
		global remove_addr
		for off in offsets:
                  if (addr, off[1], off[0]) not in remove_addr:
			if off[0] in file_map.keys():
				file_map[off[0]].append([get_type(off[1]), r, id_struct]);
			else:
				file_map[off[0]] = list([(get_type(off[1]), r, id_struct)])
		for off in offsets:
			if addr in temp_file_map.keys():
				temp_file_map[addr].append([get_type(off[1]), r, id_struct]);
			else:
				temp_file_map[addr] = list([(get_type(off[1]), r, id_struct)])
		if (len(tagmap[addr].childs) == 0):
			if (addr - base >=0):
#				output = indent*" " + "0x%x: %s;"%(addr - base, get_type(tagmap[addr]));
				output = indent*" " + "0x%x: %s;  %s"%(addr - base, get_type(tagmap[addr].size), get_off(tagmap[addr], off_map, tagmap));
			else:
#				output = indent*" " + "-0x%x: %s;"%(abs(addr - base), get_type(tagmap[addr]));
				output = indent*" " + "-0x%x: %s; %s"%(abs(addr - base), get_type(tagmap[addr].size), get_off(tagmap[addr], off_map, tagmap));
#			if (tagmap[addr].size > 0):
#				print output;
		else:
			if (addr -base >= 0):
				output = indent*" " + "0x%x: "%(addr - base);
			else:
				output = indent*" " + "-0x%x: "%(abs(addr - base));
			new_indent = len(output);
#			print output+"struct{";
			if (tagmap[addr].size > 0):
#				output = (new_indent+2)*" " + "0x0: %s;"%(get_type(tagmap[addr]));
				output = (new_indent+2)*" " + "0x0: %s;  %s"%(get_type(tagmap[addr].size), get_off(tagmap[addr], off_map, tagmap));
				#print output;
			dump_ds(tagmap, addr, (new_indent+2), off_map, False, depth+1);
			#print new_indent*" " + "};";
	return;
			
def print_region(tagmap, root, isheap, off_map):
	indent = 0;
	if (isheap):
		#print "struct {";
		indent += 2; 
		output = indent*" " + "0x0: %s; %s"%(get_type(tagmap[root].size), get_off(tagmap[root], off_map, tagmap));
                if (tagmap[root].size > 0):
                        global file_map
                        global temp_file_map
			global remove_addr
                	offsets = get_offsets(tagmap[root], root, tagmap, off_map);
                        for off in offsets:
                  	  if (root, off[1], off[0]) not in remove_addr:
                                if off[0] in file_map.keys():
                                        file_map[off[0]].append((get_type(off[1]), root, id_struct));
                                else:
                                        file_map[off[0]] = list([(get_type(off[1]), root, id_struct)])
                        for off in offsets:
                                if root in temp_file_map.keys():
                                        temp_file_map[root].append((get_type(off[1]), root, id_struct));
                                else:
                                        temp_file_map[root] = list([(get_type(off[1]), root, id_struct)])


#		if (tagmap[root].size > 0):
#			print output;
	dump_ds(tagmap, root, indent, off_map, not isheap, 0);
#	if (isheap):
#		print "}";

def process_array(tagmap, array_list, root, off_map, stack_taint):
	if stack_taint:
	  functio = max
	  start = -0xFFFFFF;
	else:
	  functio = min
	  start = 0xFFFFFFF
	final_arr = []
        for array in array_list:
                Valid = True;
		diff = {}
                for ele in range(1,len(array[0])):
			if abs(array[0][ele]-array[0][ele-1]) in diff.keys():
                          diff[abs(array[0][ele]-array[0][ele-1])] = diff[abs(array[0][ele]-array[0][ele-1])] + 1
                        else:
			  diff[abs(array[0][ele]-array[0][ele-1])] = 1
		ma = -1
		makey = -1
		for k in diff.keys():
			if ma < diff[k]:
				ma = diff[k]
				makey = k
			elif ma == diff[k]:
			  if makey not in reverse_diff.keys():
				ma = diff[k]
				makey = k
                if (not Valid):
                        continue;
		else:
		  re = []
		  ct = 0
		  for ele in range(1,len(array[0])):
		    if abs(array[0][ele]-array[0][ele-1]) == makey:
                      offsets = array[1][ele-1]
		      re.append((array[0][ele-1], offsets))
		    else:
		      ct += 1
		    if ele == len(array[0]) - 1:
                      offsets = array[1][ele]
		      re.append((array[0][ele], offsets))
		    """
		    if array[0][ele-1] not in tagmap.keys():
		      if len(re) > 1:
        	        final_arr.append(re)
			re = []
 		    """
                  #print re
		  if len(re) > 2 and ct < 2:
        	    final_arr.append(re)
	#print final_arr
        final_write = {}
 	global remove_addr
        for arr in final_arr:
          diff = abs(arr[0][0] - arr[1][0])
          # print arr,diff
          isproper = 1
	  if len(arr) > 0:
	    isproper = 1
	    temp = -1
            mi = -1
 	    result = []
	    fl = 0
	    for ele in arr:
 	      if ele[1] == "":
                if fl == 1:
                  isproper = 0
                  break
                fl = 1
                continue
	      else:
	        start = functio(start, ele[0])
                result.append(int(ele[1]))
            if isproper == 1:
              if len(result) > 2:
                result.sort()
                diff = -1
                for i in range(1,len(result)):
                  if  i == 1:
	            diff = result[i]-result[i-1]
                  if result[i] - result[i-1] == diff and diff != 0:
                    continue
                  else:
                    isproper = 0
                    break
	    if isproper == 1:
	      if len(result) > 2:
		if result[0] in final_write.keys():
		  if stack_taint:
	            final_write[result[0]].append((result, arr[0][0], start))
		  else:
	            final_write[result[0]].append((result, arr[0][0], -1))
                else:
		  if stack_taint:
  		    final_write[result[0]] = [(result, arr[0][0], start)]
		  else:
  		    final_write[result[0]] = [(result, arr[0][0], -1)]
		for ele in arr:
		  if ele[1] != "":
		    remove_addr.append((ele[0],result[1]-result[0], int(ele[1])))
	      """
              if ele[1] == "":
                if fl == 1:
                  isproper = 0
                  break
                fl = 1
                continue
	      if temp == -1:
	        temp = int(ele[1])
                mi = int(ele[1])
                result.append(mi)
                continue
              else:
                if temp + diff == int(ele[1]) or temp - diff == int(ele[1]):
                  temp = temp + diff
                  mi = min(temp, mi)
                  result.append(temp)
                else:
                  if fl == 1:
                    isproper = 0
                    break
                  fl = 1
                  continue
	    if isproper == 1:
	      if len(result) > 2:
	        final_write[mi] = result
		for ele in arr:
		  remove_addr.append((ele[0],result[1]-result[0]))
	    """
            """ 
	    for offset in start_offset:
	      for ele in arr:
	        if temp == -1:
		  temp = offset
		  mi = offset
 	 	  result.append(temp)
	          continue
		else:
		  current_ele_offsets = [item[0] for item in ele[1]]
		  if temp + diff in current_ele_offsets:
		    mi = min(temp, mi)
		    temp = temp + diff
		    result.append(temp)
		    continue;
		  elif temp - diff in current_ele_offsets:
		    mi = min(mi, temp)
		    temp = temp - diff
		    result.append(temp)
		  else:
		    isproper = 0
		    break
              if isproper == 1:
	        if len(result) > 2:
	          final_write[mi] = result
		  for ele in arr:
		    remove_addr.append((ele[0],result[1]-result[0]))
#		  print result,final_write
          for ele in arr:
            offsets = ele[1]
	    offsets = [item[0] for item in offsets]
            if len(temp) > 0:
              prev_offsets = temp[-1]
            else:
              prev_offsets = []
            fl = 1
            for offset in prev_offsets:
              if offset+diff in offsets:
                continue
              else:
                fl = 0
                break
            if fl == 1:
              if len(offsets) > 0:
                temp.append(offsets)
              else:
                break
            else:
#              print temp
              isproper = 0
              break
          if isproper == 1:
            final_off_arr.append(temp)
        for arr in final_off_arr:
          l = [item for sublist in arr for item in sublist]
         # print l
          if len(l) > 1:
            final_write[l[0]] = l
        """
	#print remove_addr
        return final_write;

def load_array(array_file):
        array_map = dict();
        try:
                f = open(array_file, "r");
                d = f.readlines();
                f.close();
        except:
                return array_map;
        i = 0;
        while (i<len(d)):
                key = int(d[i],16);
                array = list();
		offsets = list()
		#print d[i+1].strip().split(" ")
                for addr in d[i+1].strip().split(" "):
                        try:
                                array.append(int(addr.split(",")[0],16));
                                offsets.append(addr.split(",")[1][1:-1]);
                        except ValueError:
                                continue;
                if (key not in array_map.keys()):
                        array_map[key] = list();
                array_map[key].append((array, offsets));
                i += 2;
        return array_map;

def main():
	parser = argparse.ArgumentParser();
	parser.add_argument('--taint', type=str, default="./heap.taint", help='taint file');
        parser.add_argument('--array', type=str, default="./array.raw", help='array file');
	parser.add_argument('--isheap', type=str, default="y", help='indicate if the taint is belongs to heap');
	parser.add_argument('--id', type=int, default=0, help='indicate id of struct to be started with');
	args = parser.parse_args();
	taint_file = args.taint;
	array_file = args.array;
	isheap = args.isheap;
	if (not os.path.exists(taint_file)):
		parser.print_help();
		return;

	global id_struct
	id_struct = args.id

        array_map = load_array(array_file);

	f = open(taint_file, "r");
	d = f.readlines();
	f.close();
	
	stack_taint = True;
	if isheap=="y":
		stack_taint = False;
        data = {}
        with open('arr_offset.json', 'w') as fp:
            json.dump(data, fp)
	lnr = 0;
	global file_map
	global temp_file_map
	global remove_addr
	new_array_write = {}
	while (lnr < len(d)):
		line = d[lnr].split(",");
		func = int(line[0],16);
		nr = int(line[1],16);
		remove_addr = []
		tagmap = dict();
		temp_file_map = {}
		off_map = {};
		for l in d[lnr+1:lnr+1+nr]:
			t = TAG();
			t.load_from_line(l);
			#print t.file_taint[1:-1].split(",")
			k = t.file_taint.split(":")
			off_map[t.addr] = []
			for i in k:
			  off_map[t.addr].extend(list(map(int,filter(len, i[1:-1].split(",")))))
			if (t.size != 0):
				tagmap[t.addr] = t;
		root = 0;
		if (len(tagmap.keys())<1):
			lnr += 1+nr;
			continue;
		"""
		if (stack_taint):
			print "Function = %lx"%(func);
		else:
			print "MD5 = %lx"%(func);
		"""
		for addr in tagmap.keys():
			if (tagmap[addr].base not in tagmap.keys()):
				tagmap[addr].base = root;
				if (root not in tagmap.keys()):
					tagmap[root] = TAG();
					off_map[root] = []
		tagmap = process_tagmap(tagmap,root, stack_taint);
                if (func in array_map.keys()):
                        array_list = array_map[func];
                else:
                        array_list = list();
                array_write = process_array(tagmap,array_list, root, off_map, stack_taint);
		array_map.pop(func, None)
		print_region(tagmap, root, not stack_taint, off_map);
		#print "";
		lnr += 1+nr;
		new_array_write = {}
		#print temp_file_map,array_write
		for key in array_write.keys():
 		  for a in range(0, len(array_write[key])):
		    result = []
		    fl = 1
		    add = array_write[key][a][1]
		    min_addr = array_write[key][a][2]
		    if abs(array_write[key][a][0][1]-array_write[key][a][0][0]) not in  reverse_diff.keys():
		      continue
		    if add in temp_file_map.keys():
  		      for v in list(temp_file_map[add]):
		        if diff[v[0]] == abs(array_write[key][a][0][1]-array_write[key][a][0][0])or (len(array_write[key][a][0]) > 2 and addr in temp_file_map.keys() and diff[temp_file_map[add][0][0]] == abs(array_write[key][a][0][2]-array_write[key][a][0][1])):
			  result.append(v) 
		      if len(result) != 0:
			if key in new_array_write.keys():
		          new_array_write[key].append([array_write[key][a][0], [reverse_diff[abs(array_write[key][a][0][1]-array_write[key][a][0][0])], result[0][1], result[0][2], min_addr]])
			else:
		          new_array_write[key] = [[array_write[key][a][0], [reverse_diff[abs(array_write[key][a][0][1]-array_write[key][a][0][0])], result[0][1], result[0][2], min_addr]]]
		      else:
		          new_array_write[key] = [[array_write[key][a][0], [reverse_diff[abs(array_write[key][a][0][1]-array_write[key][a][0][0])], temp_file_map[add][0][1], temp_file_map[add][0][2], min_addr]]]
		    else:
		        new_array_write[key] = [[array_write[key][a][0], [reverse_diff[abs(array_write[key][a][0][1]-array_write[key][a][0][0])], -1, -1, min_addr]]]
	        with open('arr_offset.json') as fp:
        	    data = json.load(fp)
	        #print data
	        data.update(new_array_write)
	        #print data
	        with open('arr_offset.json', 'w') as fp:
	            json.dump(data, fp)
	        #print data
	#print file_map
	new_file_map = {}
	for key in sorted(file_map.keys()):
		"""
		for val in list(file_map[key]):
                  if ma < type_map[val[0]]:
                    ma = type_map[val[0]]
		result = []
		for val in list(file_map[key]):
		  if type_map[val[0]] == ma:
		    result.append([type_map[val[0]], val[1],val[2]])
		"""
		new_file_map[key] = list(file_map[key])
	"""
	for func in array_map.keys():
          array_write = process_array(tagmap,array_map[func], root, off_map);
          new_array_write = {}
          for key in array_write.keys():
            new_array_write[key] = [array_write[key], [reverse_diff[abs(array_write[key][1]-array_write[key][0])], -1, -1]]
	        #print data
	"""
        with open('arr_offset.json', 'r') as fp:
            data = json.load(fp)
	data.update(new_array_write)
	        #print data
	with open('arr_offset.json', 'w') as fp:
	     json.dump(data, fp)
	

	with open('file_offset.json', 'w') as fp:
	    json.dump(new_file_map, fp)
	f = open("id_struct","w")
	f.write(str(id_struct) + "\n")
	f.close()

if __name__=='__main__':
	sys.setrecursionlimit(10000)
	main();
