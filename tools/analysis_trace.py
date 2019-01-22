import os,sys

def ssplit(seq,splitters):
	seq=list(seq);
	if splitters and seq:
		result=[];
		begin=0;
		for end in range(len(seq)):
			if seq[end] in splitters:
				if end > begin:
					result.append(seq[begin:end]);
				begin=end+1;
		if begin<len(seq):
			result.append(seq[begin:])
		return result;
	return [seq];

def find_loop(seq, loop_dict):
	while (len(seq)>1):
		splitter = seq[0];
		sub_seq = ssplit(seq,{splitter});
		if (len(sub_seq)==0):
			return;
		if (len(sub_seq)==1):
			seq = sub_seq[0];
		else:
			seq = sub_seq[len(sub_seq)-1];
			loop_head = splitter;
			loop_body = set();
			for body in sub_seq[0:len(sub_seq)-1]:
				loop_body = loop_body | set(body);
			i = 0;
			if (loop_head not in loop_dict.keys()):
				loop_dict[loop_head] = list();
				loop_dict[loop_head].append(set()); #first for body, second for exit
				loop_dict[loop_head].append(set());
			loop_body |= loop_dict[loop_head][0];
			loop_dict[loop_head][0] = loop_body;
			loop_dict[loop_head][1] -= loop_body;
			exit_node = set();
			while (len(seq)>0):
				if seq[0] in loop_body:
					seq = seq[1:len(seq)];
				else:
					exit_node.add(seq[0]);
					break;
			loop_dict[loop_head][1] |= exit_node;
			for body in sub_seq[0:len(sub_seq)-2]:
				body.append(loop_head);
				find_loop(body,loop_dict);
		
	return;

def find_body(loop_dict):
	body_dict = dict();
	for loop_top in loop_dict.keys():
		body = loop_dict[loop_top][0];
		subbody = set();
		for loop_sub in loop_dict.keys():
			if (loop_sub in body):
				subbody |= loop_dict[loop_sub][0];
		body -= subbody;
		body_dict[loop_top] = body;
	return body_dict;

def main():
	trace_path = sys.argv[1];
	target_path = sys.argv[2];

	if (not os.path.exists(trace_path)):
		print "Please provide a valid trace file path";
		return -1;
	
	if (not os.path.exists(trace_path)):
		print "Please provide a valid target path directory";
		return -1;

	f = open(sys.argv[1],"r");
	d = f.readlines();
	f.close();

	lib_dict_fentry = dict();
	lib_dict_loop = dict();
	lib_dict_body = dict();

	i = 0;
	while (i<len(d)):
		func = d[i].split("Function : ")[1];
		sname = func.split(",")[1].split("\n")[0];
		if (sname not in lib_dict_fentry.keys()):
			lib_dict_fentry[sname] = set();
		lib_dict_fentry[sname].add(int(func.split(",")[0],16));
		i += 1;
		bbs_raw = d[i].split("\n")[0].split(",");
		bbs = list();
		for bb in reversed(bbs_raw):
			if (bb!=""):
				bbs.append(int(bb,16));
		if (sname not in lib_dict_loop.keys()):
			lib_dict_loop[sname] = dict();
		find_loop(bbs,lib_dict_loop[sname]);
		i += 1;
	
	for sname in lib_dict_loop.keys():
		lib_dict_body[sname] = find_body(lib_dict_loop[sname]);
	
	for sname in lib_dict_loop.keys():
		loop_path = os.path.join(target_path,sname);
		if (not os.path.exists(loop_path)):
			os.system("mkdir %s"%(loop_path));
		f = open(loop_path + "/loops.raw","w");
		for head in lib_dict_loop[sname].keys():
			f.write("0x%lx 0x%lx\n"%(head, len(lib_dict_body[sname][head]))); #head
			for bb in lib_dict_body[sname][head]:
				f.write("0x%lx\n"%(bb)); #body
		f.close();
	
		f = open(loop_path + "/funcs.raw","w");
		for func in lib_dict_fentry[sname]:
			f.write("0x%lx\n"%(func));
		f.close();
		
if __name__=='__main__':
	main();
