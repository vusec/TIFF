import config
import os
import operators
from operator import itemgetter
import pickle
import math
import random
import shutil
import struct

def die(msg) :
    print msg
    raise SystemExit(1)

def isDirEmpty(dn) :
    """Test if a directory is empty."""
    return os.listdir(dn) == []

def emptyDir(dn) :
    """Remove all files in a directory."""
    for fn in os.listdir(dn) :
        os.remove(os.path.join(dn, fn))
def copyd2d(src,dst):
    ''' copies all the files from src dir to dst directory.'''
    for fl in os.listdir(src):
        pfl=os.path.join(src,fl)
        shutil.copy(pfl,dst)


def readFile(fn) :
    f = open(fn, 'rb')
    d = f.read()
    f.close()
    return d

def writeFile(fn, d) :
    f = open(fn, 'wb')
    f.write(d)
    f.close()

def kill_proc(proc, timeout):
    timeout["value"] = True
    proc.kill()

#def run(cmd, timeout_sec):
#    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 #   timeout = {"value": False}
 #   timer = Timer(timeout_sec, kill_proc, [proc, timeout])
 #   timer.start()
 #   stdout, stderr = proc.communicate()
 #   timer.cancel()
 #   return proc.returncode, stdout.decode("utf-8"), stderr.decode("utf-8"), timeout["value"]

def splitFilename(fn) :
    """Split filename into base and extension (base+ext = filename)."""
    if '.' in fn :
        base,ext = fn.rsplit('.', 1)
        #ext = '.' + _ext
    else :
        ext = ''
        base = fn
    return base,ext

def delete_out_file(path):
    '''this function recives a full path to a file and deletes any file with the same file name, but different extension in the same directory. This is called only when fuzzing creates different files while executing inputs.'''
    (h,t)=os.path.split(path)
    bs,ex=splitFilename(t)
    if ex == '':
        die("Canot delete files as ther eis no extension")
    files=os.listdir(h)
    for fl in files:
        b,e=splitFilename(fl)
        if b==bs and e!=ex:
            tfl=os.path.join(h,fl)
            os.remove(tfl)


def create_files_dry(num):
    ''' This function creates num number of files in the input directory. This is called if we do not have enough initial population.
''' 
    #files=os.listdir(config.INPUTD)
    files=os.listdir(config.INITIALD)
    #files=random.sample(filef, 2)
    ga=operators.GAoperator(random.Random(),[set(),set()])
    fl=random.choice(files)
    bn, ext = splitFilename(fl)
    while (num != 0):
        fl=random.choice(files)
        fp=os.path.join(config.INITIALD,fl)
        p1=readFile(fp)
        ch1= ga.totally_random(p1,fl)
        np1=os.path.join(config.INPUTD,"ex-%d.%s"%(num,ext))
        writeFile(np1,ch1)
        num -= 1
    return 0

def taint_based_change(ch,pr):
    ''' this function takes a ch string and changes it according to the taintmap of pr input.'''
    #if pr not in config.TAINTMAP:
     #   return ch
    extVal=['\xFF\xFF\xFF\xFF','\xFE\xFF\xFF\xFF','\xFE\xFF','\xFF,\xFE','\x80\x00\x00\x00','\x7F\xFF']
    chlist=list(ch)# we change str to list because it saves space when replacing chars at multiple index in a string.
    #first lets change offsets from LEA
    if pr in config.LEAMAP:
        if len(config.LEAMAP[pr])>0:
            tof=random.sample(list(config.LEAMAP[pr]),max(1,len(config.LEAMAP[pr])/2))
            for of in tof:
                if of >= len(chlist):
                    continue
                chlist[of]=random.choice(extVal)
    if pr in config.ANALYSIS_MAP:
        cmp_offset =  config.ANALYSIS_MAP[pr][4]
        for key in cmp_offset.keys():
          start_off=key
          if config.RANDOMCOMN ==True and random.randint(0,9)>2:
            continue
          if random.randint(0,9) >config.MOSTCOMNLAST:
            try:
                l = random.choice(cmp_offset[key])
                end_off = start_off + l[0]
                s=''.join(chlist)
                s=s[:start_off]+l[1]+s[end_off:]
                chlist=list(s)
            except IndexError:
                pass
          else:
                l = cmp_offset[key][-1]
                end_off = start_off + l[0]
                s=''.join(chlist)
                s=s[:start_off]+l[1]+s[end_off:]
                chlist=list(s)
    if pr in config.TAINTMAP:
        #we want to do 2 things:
        #1. we want to take few offsets and replace them with the values based on the pr.
        #2. we want to replace values of offsets that we get in parent. this is like MOSTCOMMON operation that we do later, but only for the given parent.
        toff=random.sample(config.TAINTMAP[pr][1],len(config.TAINTMAP[pr][1])/2)
        for k in sorted(toff, reverse=True):
            if k >= len(chlist) or k<-len(chlist):# or len(config.TAINTMAP[pr][1][k]) == 0:
                continue
            if random.randint(0,9)>config.MOSTCOMNLAST:
                try:
                    tval=random.choice(config.TAINTMAP[pr][1][k])# choose arandom value 
                    chlist[k]=tval
                    chlist=list(''.join(chlist))
                except IndexError:
                    pass
            else:
                #print "len/offset is: %d/%d"%(len(chlist),k)
                chlist[k]=config.TAINTMAP[pr][1][k][-1]
                chlist=list(''.join(chlist))
   #we always take last matching value as intended value for that offset
    # now we repeat the same procedure, but for MORECOMMON offsets
    for k,v in sorted(config.MORECOMMON.iteritems(), reverse=True):
        if k>=len(chlist) or k < -len(chlist):# or len(v) ==0:
            continue
        if random.randint(0,9)>config.MOSTCOMNLAST:
            try:
                tval=random.choice(v)# we choose a random value at this offset
                chlist[k]=tval
                chlist=list(''.join(chlist))
                #print "k - v",k,tval
            except IndexError:
                #print "Exeception MOSTCOMMON",k,v
                pass
        else:
            chlist[k]=v[-1]
            chlist=list(''.join(chlist))
            #we always take last matching value as intended value for that offset
    # now we repeat the same procedure, but for MOSTCOMMON offsets
    for k,v in sorted(config.MOSTCOMMON.iteritems(), reverse=True):
        if k>=len(chlist) or k < -len(chlist):# or len(v) ==0:
            continue
        if config.RANDOMCOMN ==True:
            if random.randint(0,9)>4:
                #continue
                try:
                    tval=random.choice(list(config.ALLSTRINGS[0]))
                    chlist[k]=tval
                    chlist=list(''.join(chlist))
                    #print "k - v",k,tval
                except IndexError:
                    #print "Exeception MOSTCOMMON",k,v
                    pass
            else:
                continue
        elif random.randint(0,9)>config.MOSTCOMNLAST:
            try:
                tval=random.choice(v)
                chlist[k]=tval
                chlist=list(''.join(chlist))
                #print "k - v",k,tval
            except IndexError:
                #print "Exeception MOSTCOMMON",k,v
                pass
        else:
            chlist[k]=v[-1]
            chlist=list(''.join(chlist))
            #we always take last matching value as intended value for that offset
    

    return ''.join(chlist)

def taint_limited_change(ch):
    ''' this function takes a string and change certain offsets according to the MOSTCOMMON dictionary.'''
    chlist=list(ch)
    
    # now we repeat the same procedure, but for MORECOMMON offsets
    for k,v in config.MORECOMMON.iteritems():
        if k >= len(chlist):
            continue
        if random.randint(0,9)>config.MOSTCOMNLAST:
            try:
                tval=random.choice(v)
                chlist[k]=tval
            except IndexError:
                pass
        else:
            chlist[k]=v[-1]
            #we always take last matching value as intended value for that offset
 # now we repeat the same procedure, but for MOSTCOMMON offsets
    for k,v in config.MOSTCOMMON.iteritems():
        if k >=len(chlist):
            continue
        if random.randint(0,9)>config.MOSTCOMNLAST:
            try:
                tval=random.choice(v)
                chlist[k]=tval
            except IndexError:
                pass
        else:
            chlist[k]=v[-1]
            #we always take last matching value as intended value for that offset
    return ''.join(chlist)

"""
def createBufferOverflowinputs(input_list):
    num = 1
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)

    print input_list
    #raw_input()
    for inp in input_list:
        if inp in config.ANALYSIS_MAP:
           bn, ext = splitFilename(inp)
           fp=os.path.join(config.SPECIAL,inp)
           p1=readFile(fp)
           #ch1= ga.mutate(p1)
           arrs = config.ANALYSIS_MAP[inp][1]
           for a in arrs:
                config.NUMINPUTS += 1
                ch1=ga.add_random_string_mutate(p1, inp,a)
                #ch1=taint_based_change(ch1,inp)
                np1=os.path.join(config.INPUTD,"extra-%d.%s"%(num,ext))
                #print "extra-%d.%s"%(num,ext)
                #raw_input()
                writeFile(np1,ch1)
                num += 1
    return num
"""
def createMallocInputs(input_list):
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    interesting_8 = ["\x80","\x81","\xff","\x00","\x01","\x10","\x20","\x40","\x64","\x7f"]
    interesting_16 = ['\x80\x00','\xff\x7f','\x00\x80','\x00\xff','\x02\x00','\x03\xe8','\x04\x00','\x10\00','\x7f\xff']
    interesting_32 = ['\x80\x00\x00\x00','\xfa\x00\x00\xfa','\xff\xff\x7f\xff','\x00\x00\x80\x00','\x00\x00\xff\xff','\x00\x01\x00\x00','\x05\xff\xff\x05','\x7f\xff\xff\xff']
    #raw_input()
    num = 1
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    ma = 0
    fname = ""
    for inp in input_list:
        if inp in config.ANALYSIS_MAP:
           #ch1= ga.mutate(p1)
           arrs = len(config.ANALYSIS_MAP[inp][5])
           if (ma == 0 )or (arrs > ma):
             ma = arrs
             fname = inp
    if fname in config.ANALYSIS_MAP.keys() and fname != "":
      mi = config.ANALYSIS_MAP[fname][5]
      for off in mi:
        of=off[0]
        bn, ext = splitFilename(fname)
        fp=os.path.join(config.SPECIAL,fname)
        p1=readFile(fp)
        config.fname = fname
        if off[1] == 1:
          for v in interesting_8:
  	    fuzzed=p1[:int(of)]+v+p1[int(of)+1:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
        if off[1] == 2:
          for v in interesting_16:
  	    fuzzed=p1[:int(of)]+v+p1[int(of)+2:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
        if off[1] == 4:
          for v in interesting_32:
  	    fuzzed=p1[:int(of)]+v+p1[int(of)+4:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
	    fuzzed=p1[:int(of)]+v[::-1]+p1[int(of)+4:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
        if off[1] == 8:
          for v in interesting_32:
  	    fuzzed=p1[:int(of)]+v+p1[int(of)+4:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
	    fuzzed=p1[:int(of)]+v[::-1]+p1[int(of)+4:]
            np1=os.path.join(config.BUGD,"extramalloc-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
	    config.NUMINPUTS += 1
    return num


def createIntegerOverflowInputs(input_list):
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    interesting_8 = ["\x80","\x81","\xff","\x00","\x01","\x10","\x20","\x40","\x64","\x7f"]
    interesting_16 = ['\x80\x00','\xff\x7f','\x00\x80','\x00\xff','\x02\x00','\x03\xe8','\x04\x00','\x10\00','\x7f\xff']
    interesting_32 = ['\x80\x00\x00\x00','\xfa\x00\x00\xfa','\xff\xff\x7f\xff','\x00\x00\x80\x00','\x00\x00\xff\xff','\x00\x01\x00\x00','\x05\xff\xff\x05','\x7f\xff\xff\xff']
    #raw_input()
    num = 1
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    ma = 0
    fname = ""
    for inp in input_list:
        if inp in config.ANALYSIS_MAP:
           #ch1= ga.mutate(p1)
           arrs = len(config.ANALYSIS_MAP[inp][0]['INT16'])  + len(config.ANALYSIS_MAP[inp][0]['INT32'])
           if ((ma == 0 )or (arrs > ma)) and (inp not in config.used_int) and (inp not in config.err_in):
             ma = arrs
             fname = inp
    config.used_int.append(fname)
    if fname in config.ANALYSIS_MAP.keys() and fname != "":
      extra_16 = 0
      extra_32 = 0
      mi = config.ANALYSIS_MAP[fname][0]
      #print mi
      #raw_input()
      r = list(set(mi['INT32'])-set(config.MOSTCOMMON.keys()))
      r = random.sample(r, min(config.NEWINT, len(r)))
      if len(r) < config.NEWINT:
        extra_16 = config.NEWINT-len(r)
      r = list(set(mi['INT16'])-set(config.MOSTCOMMON.keys()))
      if len(r) < config.NEWINT:
        extra_32 = config.NEWINT-len(r)
      r = random.sample(r, min(config.NEWINT+extra_16, len(r)))
      for of in r:
        bn, ext = splitFilename(fname)
        fp=os.path.join(config.SPECIAL,fname)
        p1=readFile(fp)
        config.fname = fname
	if int(of)+2 > len(p1):
	  continue
        if config.AGGRESIVE==True:
	  for i in range(1,36):
            no = struct.unpack("<H", p1[int(of):int(of)+2])[0] - i
	    if no<0:
	      no = no+65536
            fuzzed=p1[:int(of)]+struct.pack(">H", no)+p1[int(of)+2:]
            np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
        for v in interesting_16:
  	  fuzzed=p1[:int(of)]+v+p1[int(of)+2:]
          np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
          writeFile(np1,fuzzed)
          num += 1
	  config.NUMINPUTS += 1
  	fuzzed=p1[:int(of)]+chr(255-ord(p1[int(of)]))+chr(255-ord(p1[int(of)+1]))+p1[int(of)+2:]
        np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
        writeFile(np1,fuzzed)
        num += 1
	config.NUMINPUTS += 1
      r = list(set(mi['INT32'])-set(config.MOSTCOMMON.keys()))
      r = random.sample(r, min(config.NEWINT+extra_32, len(r)))
      for of in r:
        bn, ext = splitFilename(fname)
        fp=os.path.join(config.SPECIAL,fname)
        p1=readFile(fp)
        config.fname = fname
	if int(of)+4 > len(p1):
	  continue
        if config.AGGRESIVE==True:
	  for i in range(1,36):
	    no = struct.unpack("<L", p1[int(of):int(of)+4])[0] - i
	    if no<0:
	      no = no+4294967296
            fuzzed=p1[:int(of)]+struct.pack(">I", no)+p1[int(of)+4:]
            np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
            writeFile(np1,fuzzed)
            num += 1
        for v in interesting_32:
  	  fuzzed=p1[:int(of)]+v+p1[int(of)+4:]
          np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
          writeFile(np1,fuzzed)
          num += 1
	  config.NUMINPUTS += 1
	  """
	  fuzzed=p1[:int(of)]+v[::-1]+p1[int(of)+4:]
          np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
          writeFile(np1,fuzzed)
          num += 1
	  config.NUMINPUTS += 1
	  """
  	fuzzed=p1[:int(of)]+chr(255-ord(p1[int(of)]))+chr(255-ord(p1[int(of)+1]))+chr(255-ord(p1[int(of)+2]))+chr(255-ord(p1[int(of)+3]))+p1[int(of)+4:]
        np1=os.path.join(config.BUGD,"extraint-%d.%s"%(config.NUMINPUTS,ext))
        writeFile(np1,fuzzed)
        num += 1
	config.NUMINPUTS += 1
    return num

def createBufferOverflowinputs(input_list):
    num = 1
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    string_add = [100*"A",1000*"A",10000*"A",100*"%s",10*"%s"]
    add_size = [100,1000,10000,2000,5000]
    print input_list
    #raw_input()
    ma = {}
    fname = ""
    for inp in input_list:
        if inp in config.ANALYSIS_MAP:
           #ch1= ga.mutate(p1)
           arrs = config.ANALYSIS_MAP[inp][1]
	   if len(arrs) > len(ma) and inp not in config.used_buf  and (inp not in config.err_in):
	     ma = arrs
	     fname = inp
    config.used_buf.append(fname)
    done = []
    ma = random.sample(ma, min(config.NEWINT, len(ma)))
    for a in ma:
      bn, ext = splitFilename(fname)
      fp=os.path.join(config.SPECIAL,fname)
      p1=readFile(fp)
      if (a[0], a[1]) in done:
	continue
      done.append((a[0], a[1]))
#      for v in string_add:
      for v in add_size:
        config.NUMINPUTS += 1
        config.fname = fname
        #ch1=ga.add_random_string_mutate(p1, fname,a, v)
        ch1=ga.add_random_string_mutate_2(p1, fname,a, v)
        #ch1=taint_based_change(ch1,inp)
        np1=os.path.join(config.BUGD,"extra-%d.%s"%(config.NUMINPUTS,ext))
        #print "extra-%d.%s"%(num,ext)
        #raw_input()
        writeFile(np1,ch1)
        num += 1
    print done
    #raw_input()
    return num

def create_files(num):
    ''' This function creates num number of files in the input directory. This is called if we do not have enough initial population.
    Addition: once a new file is created by mutation/cossover, we query MOSTCOMMON dict to find offsets that replace values at those offsets in the new files. Int he case of mutation, we also use taintmap of the parent input to get other offsets that are used in CMP and change them. For crossover, as there are two parents invlived, we cannot query just one, so we do a random change on those offsets from any of the parents in resulting children.
''' 
    #files=os.listdir(config.INPUTD)
    files=os.listdir(config.INITIALD)
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    while (num != 0):
        if random.uniform(0.1,1.0)>(1.0 - config.PROBCROSS) and (num >1):
            #we are going to use crossover, so we get two parents.
            par=random.sample(files, 2)
            bn, ext = splitFilename(par[0])
            #fp1=os.path.join(config.INPUTD,par[0])
            #fp2=os.path.join(config.INPUTD,par[1])
            fp1=os.path.join(config.INITIALD,par[0])
            fp2=os.path.join(config.INITIALD,par[1])
            p1=readFile(fp1)
            p2=readFile(fp2)
            ch1,ch2 = ga.crossover(p1,p2)#,par[0],par[1])
            # now we make changes according to taintflow info.
            ch1=taint_based_change(ch1,par[0])
            ch2=taint_based_change(ch2,par[1])
            np1=os.path.join(config.INPUTD,"ex-%d.%s"%(num,ext))
            np2=os.path.join(config.INPUTD,"ex-%d.%s"%(num-1,ext))
            writeFile(np1,ch1)
            writeFile(np2,ch2)
            num -= 2
        else:
            fl=random.choice(files)
            bn, ext = splitFilename(fl)
            #fp=os.path.join(config.INPUTD,fl)
            fp=os.path.join(config.INITIALD,fl)
            p1=readFile(fp)
            ch1= ga.mutate(p1,fl)
            ch1=taint_based_change(ch1,fl)
            np1=os.path.join(config.INPUTD,"ex-%d.%s"%(num,ext))
            writeFile(np1,ch1)
            num -= 1
    return 0

def createNextGeneration(fit,gn):
    ''' this funtion generates new generation. This is a variation of standard ilitism approach s.t. we either perform crossover or mutation, but noth both as done in standard approach. see createNextGeneration2() for standard implementation. '''
    files=os.listdir(config.INPUTD)
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    sfit=sorted(fit.items(),key=itemgetter(1),reverse=True)
    i=0
    bn, ext = splitFilename(sfit[i][0])
    limit=config.POPSIZE - config.BESTP
    while i< limit:
        if random.uniform(0.1,1.0)>(1.0 - config.PROBCROSS) and (i< limit-2):
            #we are going to use crossover, so we get two parents.
            #print "crossover"
            #par=random.sample(files, 2)
            fp1=os.path.join(config.INPUTD,sfit[i][0])
            fp2=os.path.join(config.INPUTD,sfit[i+1][0])
            p1=readFile(fp1)
            p2=readFile(fp2)
            ch1,ch2 = ga.crossover(p1,p2)
            np1=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i,gn,ext))
            np2=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i+1,gn,ext))
            writeFile(np1,ch1)
            writeFile(np2,ch2)
            i += 2
        else:
            #print "mutation"
            #fl=random.choice(files)
            #bn, ext = splitFilename(fl)
            fp=os.path.join(config.INPUTD,sfit[i][0])
            p1=readFile(fp)
            ch1= ga.mutate(p1,sfit[i][0])
            np1=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i,gn,ext))
            writeFile(np1,ch1)
            i += 1
    # now we need to delete last generation inputs from INPUTD dir, preserving BEST inputs.
    best=[k for k,v in sfit][:config.BESTP]
    for fl in files:
        if fl in best:
            continue
        os.remove(os.path.join(config.INPUTD,fl))
    #lets check if everything went well!!!
    if len(os.listdir(config.INPUTD))!=config.POPSIZE:
        die("Something went wrong while creating next gen inputs.. check it!")
    return 0

def createNextGeneration2(fit,gn):
    ''' this funtion generates new generation. This is the implemntation of standard ilitism approach.'''
    files=os.listdir(config.INPUTD)
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    sfit=sorted(fit.items(),key=itemgetter(1),reverse=True)
    fitnames=[k for k,v in sfit]
    # as our selection policy requires that each input that trigerred a new BB must go to the next generation, we need to find a set of BEST BBs and merge it with this set of inputs.
    best=set(fitnames[:config.BESTP]).union(set(config.SPECIALENTRY))
    #print "best",best, len(best)
    if len(best)%2 !=0:
        for nm in fitnames:
            if nm not in best:
                best.add(nm)
                break
    if config.GOTSTUCK==True:
        heavyMutate(config.INPUTD,ga,best)
    i=0
    bn, ext = splitFilename(sfit[i][0])
    #limit=config.POPSIZE - config.BESTP
    limit=config.POPSIZE - len(best)
    while i< limit:
        cutp=int(random.uniform(0.4,1.0)*len(fitnames))
        #we are going to use crossover s.t. we want to choose best parents frequently, but giving chance to less fit parents also to breed. the above cut gives us an offset to choose parents from.
        #print "crossover"
        par=random.sample(fitnames[:cutp], 2)
        fp1=os.path.join(config.INPUTD,par[0])
        fp2=os.path.join(config.INPUTD,par[1])
        p1=readFile(fp1)
        p2=readFile(fp2)
        ch1,ch2 = ga.crossover(p1,p2)
        np1=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i,gn,ext))
        np2=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i+1,gn,ext))
        #now we do mutation on these children, one by one
        if random.uniform(0.1,1.0)>(1.0 - config.PROBMUT):
            mch1= ga.mutate(ch1)
            writeFile(np1,mch1)
        else:
            writeFile(np1,ch1)
        if random.uniform(0.1,1.0)>(1.0 - config.PROBMUT):
            mch2= ga.mutate(ch2)
            writeFile(np2,mch2)
        else:
            writeFile(np2,ch2)
        i += 2
    
    # now we need to delete last generation inputs from INPUTD dir, preserving BEST inputs.
    #best=[k for k,v in sfit][:config.BESTP]
    for fl in files:
        if fl in best:
            continue
        os.remove(os.path.join(config.INPUTD,fl))
    #lets check if everything went well!!!
    if len(os.listdir(config.INPUTD))!=config.POPSIZE:
        die("Something went wrong while creating next gen inputs.. check it!")
    return 0

def createNextGeneration3(fit,gn):
    ''' this funtion generates new generation. This is the implemntation of standard ilitism approach. We are also addressing "input bloating" issue  by selecting inputs based on its length. the idea is to select inputs for crossover their lenths is less than the best input's length. Oterwise, such inputs directly go for mutation whereby having a chance to reduce their lengths.'''
    
    files=os.listdir(config.INPUTD)
    ga=operators.GAoperator(random.Random(),config.ALLSTRINGS)
    sfit=sorted(fit.items(),key=itemgetter(1),reverse=True)
    bfp=os.path.join(config.INPUTD,sfit[0][0])
    bestLen=os.path.getsize(bfp)
    fitnames=[k for k,v in sfit]
    # as our selection policy requires that each input that trigerred a new BB must go to the next generation, we need to find a set of BEST BBs and merge it with this set of inputs.
    best=set(fitnames[:config.BESTP])#.union(set(config.SPECIALENTRY))
    #best.update(config.CRASHIN)
    #print "best",best, len(best)
    if len(best)%2 !=0:
        for nm in fitnames:
            if nm not in best:
                best.add(nm)
                break
   
    if config.GOTSTUCK==True:
        heavyMutate(config.INPUTD,ga,best)
    #here we check for file length and see if we can reduce lengths of some.
    if gn%config.skipGen ==0:
        mn,mx,avg=getFileMinMax(config.INPUTD)
        filesTrim(config.INPUTD,avg,bestLen,config.minLength,ga, best)
    i=0
    bn, ext = splitFilename(sfit[i][0])
    #limit=config.POPSIZE - config.BESTP
    limit=config.POPSIZE - len(best)
    #print "nextgen length %d - %d\n"%(limit, len(best))
    #raw_input("enter key")
    crashnum=0 #this variable is used to count new inputs generated with crashing inputs. 
    emptyDir(config.INTER)
    copyd2d(config.SPECIAL,config.INTER)
    if config.ERRORBBON==True:
        copyd2d(config.INITIALD,config.INTER)
    while i< limit:
        cutp=int(random.uniform(0.4,0.8)*len(fitnames))
        #we are going to use crossover s.t. we want to choose best parents frequently, but giving chance to less fit parents also to breed. the above cut gives us an offset to choose parents from. Note that last 10% never get a chance to breed.
        #print "crossover"
        par=random.sample(fitnames[:cutp], 2)
        fp1=os.path.join(config.INPUTD,par[0])
        fp2=os.path.join(config.INPUTD,par[1])
        inpsp=os.listdir(config.INTER)
        #if len(config.SPECIALENTRY)>0 and random.randint(0,9) >6:
        #    fp1=os.path.join(config.INPUTD,random.choice(config.SPECIALENTRY))
        #if len(config.CRASHIN)>0 and random.randint(0,9) >4 and crashnum<5:
        #    fp2=os.path.join(config.INPUTD,random.choice(config.CRASHIN))
        #    crashnum += 1
        sin1='xxyy'
        sin2='yyzz'
        if len(inpsp)>0:
            if random.randint(0,9) >config.SELECTNUM:
                sin1=random.choice(inpsp)
                fp1=os.path.join(config.INTER,sin1)
            if random.randint(0,9) >config.SELECTNUM:
                sin2=random.choice(inpsp)
                fp2=os.path.join(config.INTER,sin2)
        np1=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i,gn,ext))
        np2=os.path.join(config.INPUTD,"new-%d-g%d.%s"%(i+1,gn,ext))
        p1=readFile(fp1)
        p2=readFile(fp2)
        if (len(p1) > bestLen) or (len(p2) > bestLen):
            #print "no crossover"
            #mch1= ga.mutate(p1)
            if sin1 != 'xxyy':
                mch1= ga.mutate(p1,sin1)
                mch1=taint_based_change(mch1,sin1)
            else:
                mch1= ga.mutate(p1,par[0])
                mch1=taint_based_change(mch1,par[0])
            #mch2= ga.mutate(p2)
            if sin2 !='yyzz':
                mch2= ga.mutate(p2,sin2)
                mch2=taint_based_change(mch2,sin2)
            else:
                mch2= ga.mutate(p2,par[1])
                mch2=taint_based_change(mch2,par[1])
            if len(mch1)<3 or len(mch2)<3:
                die("zero input created")
            writeFile(np1,mch1)
            writeFile(np2,mch2)
            i+=2
            #continue
        else:
            #print "crossover"
            ch1,ch2 = ga.crossover(p1,p2)
            #now we do mutation on these children, one by one
            if random.uniform(0.1,1.0)>(1.0 - config.PROBMUT):
                #mch1= ga.mutate(ch1)
                if sin1 !='xxyy':
                    mch1= ga.mutate(ch1,sin1)
                    mch1=taint_based_change(mch1,sin1)
                else:
                    mch1= ga.mutate(ch1,par[0])
                    mch1=taint_based_change(mch1,par[0])
                if len(mch1)<3:
                    die("zero input created")
                writeFile(np1,mch1)
            else:
                if sin1 != 'xxyy':
                    ch1=taint_based_change(ch1,sin1)
                else:
                    ch1=taint_based_change(ch1,par[0])
                writeFile(np1,ch1)
            if random.uniform(0.1,1.0)>(1.0 - config.PROBMUT):
                #mch2= ga.mutate(ch2)
                if sin2 !='yyzz':
                    mch2= ga.mutate(ch2,sin2)
                    mch2=taint_based_change(mch2,sin2)
                else:
                    mch2= ga.mutate(ch2,par[1])
                    mch2=taint_based_change(mch2,par[1])

                if len(mch2)<3:
                    die("zero input created")
                writeFile(np2,mch2)
            else:
                if sin2 != 'yyzz':
                    ch2=taint_based_change(ch2,sin2)
                else:
                    ch2=taint_based_change(ch2,par[1])

                writeFile(np2,ch2)
            i += 2
    
    # now we need to delete last generation inputs from INPUTD dir, preserving BEST inputs.
    #best=[k for k,v in sfit][:config.BESTP]
    #print "gennext loop ",i
    #raw_input("enterkey..")
    for fl in files:
        if fl in best:
            continue
        os.remove(os.path.join(config.INPUTD,fl))
    #lets check if everything went well!!!
    if len(os.listdir(config.INPUTD))!=config.POPSIZE:
        die("Something went wrong while creating next gen inputs.. check it!")
    return 0

def prepareBBOffsets():
    ''' This functions load pickle files to prepare BB weights and strings found in binary. The strings are read from a pickle file, generated by IDAPython. This file contains a tuple of two sets (A,B). A= set of all strings found at CMP instructions. B= set of individual bytes, generated from strings of A and CMP.
'''
    tempFull=set()
    tempByte=set()
    for i in range(config.LIBNUM):
        pFD=open(config.LIBPICKLE[i],"r")
        tBB=pickle.load(pFD)
        for tb in tBB:
            ad=tb+int(config.LIBOFFSETS[i],0)
            # we do not consider weights greater than BBMAXWEIGHT and we take log2 of weights as final weight.
            if tBB[tb][0]>config.BBMAXWEIGHT:
                config.ALLBB[ad]=int(math.log(config.BBMAXWEIGHT,2))
            else:
                config.ALLBB[ad]=int(math.log((tBB[tb][0]+1),2))
            if i==0:
                config.cAPPBB.add(ad)
            config.cALLBB.add(ad)
        pFD.close()
        tFD=open(config.NAMESPICKLE[i],"r")
        tdata=pickle.load(tFD)
        tempFull.update(tdata[0])# set of full strings from the binary
        tempByte.update(tdata[1])# set of individual bytes from the binary
    if config.NOFFBYTES == True:
	tempFull.discard('\xFF\xFF\xFF\xFF')
	tempFull.discard('\xff\xff\xff\xff')
	tempFull.discard('\x00\xFF\xFF\xFF\xFF')
	tempFull.discard('\x00\xff\xff\xff\xff')
    if config.ARCHLIL == True:
        # lets reverse all of the full strings.
        tf=map(lambda x: x[::-1], tempFull)
        tempFull=set(tf[:])
        print tempFull
        #raw_input("press any key...")
    config.ALLSTRINGS.append(tempFull.copy())
    config.ALLSTRINGS.append(tempByte.copy())
    
def prepareLibBBOffsets(loffset):
    ''' This functions load pickle files to prepare BB weights in the case of loadtime image address change.
'''
    config.ALLBB.clear()
    config.cALLBB.clear()
    for i in range(config.LIBNUM):
        pFD=open(config.LIBPICKLE[i],"r")
        tBB=pickle.load(pFD)
        if i==0:
            for tb in tBB:
                ad=tb+int(config.LIBOFFSETS[i],0)
                config.ALLBB[ad]=tBB[tb][0]
                #config.cAPPBB.add(ad)
                config.cALLBB.add(ad)
        else:
            for tb in tBB:
                ad=tb+loffset
                config.ALLBB[ad]=tBB[tb][0]
                config.cALLBB.add(ad)
        pFD.close()

def fitnesCal2(bbdict, cinput,ilen):
    '''
    calculates fitness of each input based on its execution trace. The difference from "fitnesCal()" is that it again multiplies fitnes score by the number of BB executed.
    '''
    
    config.GOTSPECIAL=False
    score=0.0
    bbNum=0
    tempset=config.ERRORBBALL.union(config.TEMPERRORBB)
    # calculate negative weight for error BBs
    numEBB=len(set(bbdict)&tempset)
    if numEBB>0:
        ew=-len(bbdict)*config.ERRORBBPERCENTAGE/numEBB
    tset=set(bbdict)-tempset # we make sure that newly discovered BBs are not related to error BB.
    config.cPERGENBB.update(tset)
    if not tset <=config.SEENBB:# and not tset <=tempset:
        diffb=tset-config.SEENBB
        config.GOTSPECIAL=True
        config.SEENBB.update(diffb)
        #todel=set()
        #tofix=set()
        #for tk, tv in config.TMPBBINFO.iteritems():
        #    if tv <= diffb:
        #        todel.add(tk):
            #elif len(tv & diffb)>0:
            #    tofix.add(tk)
            #else:
            #    pass
        #for tb in todel:
        #    del config.TMPBBINFO[tb]
        #    if config.LESSPRUNE==True:
        #        config.SPECIALDEL.add(tb)
        #for tb in tofix:
        #    config.TMPBBINFO[tb].difference_update(diffb)
        #config.TMPBBINFO[cinput]=diffb.copy()
       # del tempset
       # del todel
       # del diffb
       # del tofix
        #return 10 #some random value as we don;t care much about fitness score of such input as they go to next gen anyway!
    for bbadr in bbdict: 
        #config.cPERGENBB.add(bbadr)#added for code-coverage
        #if bbadr in tempset:#config.ERRORBBALL:
        #    continue
        #bbNum +=1
        bbfr=bbdict[bbadr]
        if bbfr > config.BBMAXFREQ:
            bbfr = config.BBMAXFREQ
        lgfr=int(math.log(bbfr+1,2)) #1 is added to avoid having log(1)=0 case
        #if bbadr not in config.SEENBB:
        #    config.SEENBB.add(bbadr)
        #    config.SPECIALENTRY.append(cinput)
        if bbadr in tempset:
            #print"[0x%x] Error BB hit (%f ) !"%(bbadr,ew)
            score=score+(lgfr*ew)
        elif bbadr in config.ALLBB:
            #print"[0x%x] BB hit (%d - %f) !"%(bbadr,bbfr,config.ALLBB[bbadr])
            score=score+(lgfr*config.ALLBB[bbadr])
            bbNum +=1
        else:
            #print"[0x%x] BB missed (%d) !"%(bbadr,bbfr)
            score = score+lgfr
            bbNum +=1
    del tempset
    #print "BBNum", bbNum
    #return round((score*bbNum)/(ilen*1.0),2)
    #return (score*bbNum)/totalFreq
    if ilen > config.MAXINPUTLEN:
        return (score*bbNum)/int(math.log(ilen+1,2))
    else:
        return score*bbNum
 
def fitnesNoWeight(bbdict, cinput,ilen):
    '''
    calculates fitness of each input based on its execution trace. The difference from "fitnesCal()" is that it again multiplies fitnes score by the number of BB executed.
    '''
    
    score=0.0
    bbNum=0
    tempset=config.ERRORBBALL.union(config.TEMPERRORBB)
    tset=set(bbdict)
    config.cPERGENBB.update(tset)
    if not tset <=config.SEENBB and not tset <=tempset:
        diffb=tset-config.SEENBB
        config.SEENBB.update(diffb)
        todel=set()
        tofix=set()
        for tk, tv in config.TMPBBINFO.iteritems():
            if tv <= diffb:
                todel.add(tk)
            elif len(tv & diffb)>0:
                tofix.add(tk)
            else:
                pass
        for tb in todel:
            del config.TMPBBINFO[tb]
        for tb in tofix:
            config.TMPBBINFO[tb].difference_update(diffb)
        config.TMPBBINFO[cinput]=diffb.copy()
       # del tempset
        del todel
        del diffb
        del tofix
        #return 10 #some random value as we don;t care much about fitness score of such input as they go to next gen anyway!
    for bbadr in bbdict: 
        #config.cPERGENBB.add(bbadr)#added for code-coverage
        if bbadr in tempset:#config.ERRORBBALL:
            continue
        bbNum +=1
        bbfr=bbdict[bbadr]
        if bbfr > config.BBMAXFREQ:
            bbfr = config.BBMAXFREQ
        lgfr=int(math.log(bbfr+1,2)) #1 is added to avoid having log(1)=0 case
        #if bbadr not in config.SEENBB:
        #    config.SEENBB.add(bbadr)
        #    config.SPECIALENTRY.append(cinput)
        #if bbadr in config.ALLBB:
        #    print"[0x%x] BB hit (%d - %f) !"%(bbadr,bbfr,config.ALLBB[bbadr])
        #    score=score+(lgfr*config.ALLBB[bbadr])
        #else:
        #    print"[0x%x] BB missed (%d) !"%(bbadr,bbfr)
        score = score+lgfr
    del tempset
    #print "BBNum", bbNum
    #return round((score*bbNum)/(ilen*1.0),2)
    #return (score*bbNum)/totalFreq
    if ilen > config.MAXINPUTLEN:
        return (score*bbNum)/int(math.log(ilen+1,2))
    else:
        return score*bbNum
    #return (score*bbNum)/int(math.log(ilen+1,2))
                
def getFileMinMax(dirP):
    files=os.listdir(dirP)
    sizes=[os.path.getsize(os.path.join(dirP,s)) for s in files]
    return min(sizes),max(sizes), sum(sizes)/len(sizes)

def filesTrim(dpath,aveLen,bestLen,initLen, ga, bestin):
    '''
    this function is used to trim the lenghts of inputs.
    TODO: we can also ignore best inputs. For that we need to have another parameter that contains names of best inputs.
    '''
    files=os.listdir(dpath)
    if aveLen> 100*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1,1.0)>0.3:
                tpath=os.path.join(dpath,fl)
                if os.path.getsize(tpath)>bestLen:
                    fd=open(tpath,'r+b')
                    p=fd.read()
                    ch=ga.double_eliminate(p,fl)
                    ch=taint_based_change(ch,fl)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    elif aveLen> 50*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1,1.0)>0.3:
                tpath=os.path.join(dpath,fl)
                if os.path.getsize(tpath)>bestLen:
                    fd=open(tpath,'r+b')
                    p=fd.read()
                    ch=ga.eliminate(p,fl)
                    ch=taint_based_change(ch,fl)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    elif aveLen> 10*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1,1.0)>0.4:
                tpath=os.path.join(dpath,fl)
                if os.path.getsize(tpath)>bestLen:
                    fd=open(tpath,'r+b')
                    p=fd.read()
                    ch=ga.eliminate_random(p,fl)
                    ch=taint_based_change(ch,fl)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    else:
        pass

def calculateCov():
    #for tval in config.PREVBBINFO.itervalues():
    #    config.cPERGENBB.update(tval)
    
    if len(config.cAPPBB) == 0:
 	return 0,0
    if config.LIBNUM==1:
        #return 100-(len(config.cAPPBB.difference(config.cPERGENBB))*100/len(config.cAPPBB)),0
        return 100-(len(config.cAPPBB.difference(config.SEENBB))*100/len(config.cAPPBB)),0
    else:
        #return 100-(len(config.cAPPBB.difference(config.cPERGENBB))*100/len(config.cAPPBB)),100-(len(config.cALLBB.difference(config.cPERGENBB))*100/len(config.cALLBB))
        return 100-(len(config.cAPPBB.difference(config.SEENBB))*100/len(config.cAPPBB)),100-(len(config.cALLBB.difference(config.SEENBB))*100/len(config.cALLBB))
        

def heavyMutate(dpath,ga,bestin):
    ''' this function performs heavy mutation on the current generation.
'''
    files=os.listdir(dpath)
    print "starting heavy mutation..."
    for fl in files:
        if fl in bestin:
            continue
        tpath=os.path.join(dpath,fl)
        fd=open(tpath,'r+b')
        p=fd.read()
        ch=ga.double_full_mutate(p,fl)
        ch=taint_based_change(ch,fl)
        fd.seek(0)
        fd.truncate()
        fd.write(ch)
        fd.close()
        
def remove_files(fitnes):
    ''' This function removes files which are longer s.t. there are shorter files with same fitness value.'''

    

