import os, sys
import argparse

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

def process_tagmap(tagmap, root):
	sorted_addr = sorted(tagmap.keys());
#Detect loops, and use the lower one
	for addr in sorted_addr:
		base_addr = tagmap[addr].base;
		accessed  = set();
		accessed.add(addr);
		while (base_addr != root) and(base_addr not in accessed):
			accessed.add(base_addr);
			base_addr = tagmap[base_addr].base;
		if (base_addr != root):
			base_addr = sorted(accessed)[0];
			tagmap[base_addr].base = root;
		#print addr,base_addr,tagmap[addr].base,tagmap[base_addr].base
#Detect base above child
#	print sorted_addr
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

def get_type(tag):
	if tag.isArray:
		return "ARR*";
	if tag.isPointer:
		return "VOID*";
	else:
		return "INT%d"%(tag.size*8);
	
def dump_ds(tagmap, base, indent, isReverse=False):
	childs = sorted(tagmap[base].childs, reverse=isReverse);
	for addr in childs:
		print addr,tagmap[addr].isArray
		if (len(tagmap[addr].childs) == 0):
			if (addr - base >=0):
				output = indent*" " + "0x%x: %s;"%(addr - base, get_type(tagmap[addr]));
			else:
				output = indent*" " + "-0x%x: %s;"%(abs(addr - base), get_type(tagmap[addr]));
			if (tagmap[addr].size > 0):
				print output;
		else:
			if (addr -base >= 0):
				output = indent*" " + "0x%x: "%(addr - base);
			else:
				output = indent*" " + "-0x%x: "%(abs(addr - base));
			new_indent = len(output);
			print output+"struct{";
			if (tagmap[addr].size > 0):
				output = (new_indent+2)*" " + "0x0: %s;"%(get_type(tagmap[addr]));
				print output;
			dump_ds(tagmap, addr, (new_indent+2), False);
			print new_indent*" " + "};";
	return;
			
def print_region(tagmap, root, isheap):
	indent = 0;
	if (isheap):
		print "struct {";
		indent += 2; 
		output = indent*" " + "0x0: %s;"%(get_type(tagmap[root]));
		if (tagmap[root].size > 0):
			print output;
	dump_ds(tagmap, root, indent, not isheap);
	if (isheap):
		print "}";

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
		for addr in d[i+1].split(" "):
			try:
				array.append(int(addr,16));
			except ValueError:
				continue;
		if (key not in array_map.keys()):
			array_map[key] = list();
		array_map[key].append(array);
		i += 2;
	return array_map;

def process_array(tagmap, array_list, root):
#	return tagmap;
	for array in array_list:
		Valid = True;
		for ele in array:
			if (ele not in tagmap.keys()):
				Valid = False;
				break;
		if (not Valid):
			continue;
	return tagmap;

def main():
	parser = argparse.ArgumentParser();
	parser.add_argument('--taint', type=str, default="./heap.taint", help='taint file'); 
	parser.add_argument('--array', type=str, default="./array.raw", help='array file');
	parser.add_argument('--isheap', type=str, default="y", help='indicate if the taint is belongs to heap');
	args = parser.parse_args();
	taint_file = args.taint;
	array_file = args.array;
	isheap = args.isheap;
	
	array_map = load_array(array_file);

	f = open(taint_file, "r");
	d = f.readlines();
	f.close();
	
	stack_taint = True;
	if isheap=="y":
		stack_taint = False;
	
	lnr = 0;
	while (lnr < len(d)):
		line = d[lnr].split(",");
		func = int(line[0],16);
		nr = int(line[1],16);
		
		tagmap = dict();
		for l in d[lnr+1:lnr+1+nr]:
			t = TAG();
			t.load_from_line(l);
			if (t.size != 0):
				tagmap[t.addr] = t;
		root = 0;
		if (len(tagmap.keys())<1):
			lnr += 1+nr;
			continue;
		if (stack_taint):
			print "Function = %lx"%(func);
		else:
			print "MD5 = %lx"%(func);
		for addr in tagmap.keys():
			if (tagmap[addr].base not in tagmap.keys()):
				tagmap[addr].base = root;
				if (root not in tagmap.keys()):
					tagmap[root] = TAG();
		print(sorted(tagmap.keys()))
		tagmap = process_tagmap(tagmap,root);
		if (func in array_map.keys()):
			array_list = array_map[func];
		else:
			array_list = list();
		tagmap = process_array(tagmap,array_list, root);
		print_region(tagmap, root, not stack_taint);
		print "";
		lnr += 1+nr;

if __name__=='__main__':
	main();
