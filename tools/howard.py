import os, sys
import time
import subprocess

def main():
	assert(len(sys.argv)>1);
	assert(os.environ['PIN_HOME']!="");
	PINHOME = os.environ['PIN_HOME'];
        filename = sys.argv[1];
	workdir, binary = os.path.split(sys.argv[2]);
        print filename,workdir,binary
	para_str = "";
	for i in range(3,len(sys.argv)):
		para_str += sys.argv[i] + " ";

	dir_path = os.path.dirname(os.path.realpath(__file__))
	res_dir = os.path.join(dir_path,"howard");
	if (not os.path.exists(res_dir)):
		os.system("mkdir %s"%(res_dir));
	print res_dir,para_str
	start = time.time()
	os.system(PINHOME+"/pin.sh -t ../func_detect/func_detect.so -o ./trace.log -- %s 1>output1.log 2>errmsg1.log"%(os.path.join(workdir, binary)+" "+para_str));
	end = time.time()
	print end-start
	start = time.time()
	os.system("python ./analysis_trace.py ./trace.log %s"%(res_dir));
	end = time.time()
	print end-start
	os.system("mv ./trace.log %s/"%(res_dir));
	print "==========================Loop  Done========================="
	start = time.time()
        os.system(PINHOME+"/pin.sh -t ../taint_detect/tools/libdft-dta.so -img_dir %s -filename %s -maxoff 1 -- %s 1>output.log 2>errmsg.log"%(res_dir,filename, os.path.join(workdir, binary)+" "+para_str));
        
	end = time.time()
	print end-start
	print "==========================Taint Done========================="

if __name__=="__main__":
	main();

