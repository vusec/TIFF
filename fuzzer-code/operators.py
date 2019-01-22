"""
operators.py
    This files implements GA operators viz mutation and crossover for fuzzing data.

This is partly based on mutation implementation by Jesse Burns (jesse@isecpartners.com)
"""
import random
import config
import binascii as bina
import mutation_helper

class GAoperator:
    """ create it with a random and have it manipulate data for you. """
    DENOM = 50 # change at most 0-2 % of the binary with each fuzz
    r = None
    int_slide_position = 0
    slide_step = 1
    #ALL_CHARS = ''.join([chr(n) for n in xrange(256)])
    ALL_CHARS = [chr(n) for n in xrange(256)]
    HIGH_CHARS= [chr(n) for n in xrange(128,256)]
    TWO_BYTES = [format(n, '#06x')[2:].decode('hex') for n in xrange(0,65536)]
    MAJOR_TWO_BYTES = [TWO_BYTES[0], TWO_BYTES[1], TWO_BYTES[-1], TWO_BYTES[-2]]
    interesting_8 = ["\x80","\x81","\xff","\x00","\x01","\x10","\x20","\x40","\x64","\x7f"]
    interesting_16 = ['\x80\x00','\xff\x7f','\x00\x80','\x00\xff','\x02\x00','\x03\xe8','\x04\x00','\x10\00','\x7f\xff']
    interesting_32 = ['\x80\x00\x00\x00','\xfa\x00\x00\xfa','\xff\xff\x7f\xff','\x00\x00\x80\x00','\x00\x00\xff\xff','\x00\x01\x00\x00','\x05\xff\xff\x05','\x7f\xff\xff\xff']  
    def __init__(self, random_object, extra, demoninator = 50):
        ''' the 3rd parameter extra us a list of two sets. 1st set is a set of full strings from binary, whereas 2nd set is a set of individual bytes from those strings.
''' 
        self.DENOM = demoninator
        self.r = random_object
        self.full=list(extra[0])
        self.obytes=list(extra[1])
        if len(self.full)>0:
            self.allStrings=[self.full,self.full,self.HIGH_CHARS,self.obytes]
            #self.allStrings=[self.full,self.full,self.full,self.obytes]
        elif len(self.obytes)>0:
            #self.allStrings=[self.ALL_CHARS,self.obytes,self.obytes,self.obytes]
            self.allStrings=[self.obytes,self.obytes,self.HIGH_CHARS]
        else:
            self.allStrings=[self.ALL_CHARS]
    #print len(self.allStrings)
    
    #print self.bytes
    #print self.full
    #print self.ALL_CHARS

  #def random_string(self, size, char_set = ALL_CHARS):
    #return ''.join([self.r.choice(char_set) for n in xrange(size)] 
    def get_cut(self,size,fl):
        print "in get_cut\n"
        if len(config.TAINTMAP)>0 and random.randint(0,9)>3:
            onlyCom=False
            if fl in config.TAINTMAP:
                tof=config.TAINTMAP[fl][0]
		arr=config.ANALYSIS_MAP[fl][1]
            else:
                tfl=self.r.choice(config.TAINTMAP.keys())
                tof=config.TAINTMAP[tfl][0]
		arr=config.ANALYSIS_MAP[tfl][1]
            if config.RANDOMCOMN ==True and random.randint(0,9)>5:
                tset=set(tof)
        else:
            onlyCom=True
            
        if size == 0:
            return sel.r.randint(0,10)
        #right=False
        #while right!=True:
            #cut_pos = self.r.randint(0, size)
        if onlyCom==False:
            tset=set(tof)-set(config.MOSTCOMMON)
            if config.RANDOMCOMN == True and random.randint(0,9) > 5:
                tset=set(tof)
            if len(tset)>0:
                ltset=filter(lambda x:x<size, tset)
                if len(ltset)>0:
                    cut_pos=self.r.choice(ltset)
                    print "offset %d"%(cut_pos,)
                else:
                    cut_pos=self.r.randint(0,size)
                    print "random offset %d"%(cut_pos,)
            else:
                right=False
                ct = 0
                while right ==False:
                    ct += 1
                    cut_pos = self.r.randint(0, size)
                    if cut_pos not in config.MOSTCOMMON:
                        right = True
                        print "random offset %d"%(cut_pos,)
                    if ct > 50:
                        right = True

                #if cut_pos not in config.MOSTCOMMON and cut_pos in tof:
                #    right = True
        else:
            right=False
            ct = 0
            while right ==False:
                cut_pos = self.r.randint(0, size)
                ct += 1
                if cut_pos not in config.MOSTCOMMON:
                    right = True
                    print "random offset %d"%(cut_pos,)
                if ct > 50:
                        right = True

        return cut_pos
 
    def get_cut_range(self,size,fl,r1,r2):
        print "in get_cut\n"
        if len(config.TAINTMAP)>0 and random.randint(0,9)>3:
            onlyCom=False
            
            if fl in config.TAINTMAP:
                tof=config.TAINTMAP[fl][0]
            else:
                tfl=self.r.choice(config.TAINTMAP.keys())
                tof=config.TAINTMAP[tfl][0]
        else:
            onlyCom=True
            

        #right=False
        #while right!=True:
            #cut_pos = self.r.randint(0, size)
        if onlyCom==False:
	    tset1=set(tof)-set(config.MOSTCOMMON)
	    tset=tset1-set(range(0,r1)+range(r2,size))
            if len(tset)>0:
                ltset=filter(lambda x:x<size and x>0, tset)
                if len(ltset)>0:
                    cut_pos=self.r.choice(ltset)
                    print "offset %d"%(cut_pos,)
                else:
                    cut_pos=self.r.randint(r1,r2)
                    print "random offset %d"%(cut_pos,)
            else:
                right=False
                cut_pos = self.r.randint(r1, r2)
		return cut_pos

                #if cut_pos not in config.MOSTCOMMON and cut_pos in tof:
                #    right = True
        else:
            right=False
            cut_pos = self.r.randint(r1, r2)
	    return cut_pos
        return cut_pos  

    def random_string(self, size, source=None):
        if source is None:
            source=self.allStrings
        result=''
        while len(result)<size:
            result=result+self.r.choice(self.r.choice(source))
        #return ''.join([self.r.choice(self.r.choice(self.allStrings)) for n in xrange(size)])
        return result

    def random_string_16(self, size, source=None):
        if source is None:
            source=self.TWO_BYTES
        result=''
        while len(result)<size:
	    if random.randint(0,9) > 3:
              result=result+self.r.choice(self.TWO_BYTES)
	    else:
              result=result+self.r.choice(self.MAJOR_TWO_BYTES)
        #return ''.join([self.r.choice(self.r.choice(self.allStrings)) for n in xrange(size)])
        return result

    def random_string_32(self, size, source=None):
        if source is None:
            source=self.allStrings
        result=''
        while len(result)<size:
	    mutate = self.r.choice(mutation_helper.values_32bit)
            result=result+mutate['value']
        #return ''.join([self.r.choice(self.r.choice(self.allStrings)) for n in xrange(size)])
        return result

    def change_int8(self, original, fl):
        lorig = list(original)
	int8_off = []
        print "in change_int8"
        if len(config.ANALYSIS_MAP) > 0:
  	  if fl in config.ANALYSIS_MAP:
            int8_off=config.ANALYSIS_MAP[fl][0]['INT8']
 	  else:
            tfl=self.r.choice(config.ANALYSIS_MAP.keys())
            int8_off=config.ANALYSIS_MAP[tfl][0]['INT8']
        else:
          return self.change_bytes(original, fl)
        int8_off = set(int8_off)-set(config.MOSTCOMMON)
	offs=self.r.sample(int8_off,max(1,len(int8_off)/4))
        for off in offs:
          if off>len(lorig)-1 or off< -len(lorig):
            continue
          if random.randint(0,9)>3 and len(self.obytes) > 2:
            lorig[off] = self.r.choice(self.obytes)
          else:
            lorig[off] = self.r.choice(self.ALL_CHARS)
        if len(int8_off) > 0:
          result=''.join([e for e in lorig])
	print offs,result
  	#print "in change_int8", fl
	#gw = raw_input()
        return result

    def int16_swap(self, original, fl):
        #lorig = list(original)
        int16_off = []
        print "in int16_swap"
        if len(config.ANALYSIS_MAP) > 0:
  	  if fl in config.ANALYSIS_MAP:
            int16_off=config.ANALYSIS_MAP[fl][0]['INT16']
 	  else:
            tfl=self.r.choice(config.ANALYSIS_MAP.keys())
            int16_off=config.ANALYSIS_MAP[tfl][0]['INT16']
        else:
          return self.change_bytes(original, fl)
        off1 = self.r.choice(int16_off)
        off2 = self.r.choice(int16_off)
	of1=min(off1,off2)
	of2=max(off1,off2)
 	byte1 = original[of1:of1+2]
 	byte2 = original[of2:of2+2]
	result = original[:of1]+byte2+original[of1+2:of2]+byte1+original[of2+2:]
	"""
        if len(offs) == 0:
    	  result = original
          for off in offs:
            fuzzed = '%s%d%s' %(result[:off],random.randint(0, 0xFFFF),data[off+2:])
            result = fuzzed
          print "in int16_mutator", offs, ':'.join(x.encode('hex') for x in result)
          gw=raw_input()
          return result
        else:
          return self.change_bytes(original, fl)
        """
	return result

    def eliminate_random(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        #cut_pos = self.r.randint(0, size - cut_size)
        cut_pos = self.get_cut(size - cut_size,fl)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def eliminate_random_end(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(size/2, size - cut_size)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def eliminate_random_string(self, original, fl):
        size = len(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
            arr=config.ANALYSIS_MAP[fl][1]
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
            arr=config.ANALYSIS_MAP[tfl][1]

        if len(arr) > 0 and random.randint(0, 9) > 3:
            arr_sel = self.r.choice(arr)
            start_offset = arr_sel[0]
            end_offset = arr_sel[1]
            type_arr = arr_sel[2]
            add_size = max(1, self.r.randint(1, ((end_offset-start_offset)/type_arr) + 1))
            cut_pos1 = start_offset
            cut_pos2 = end_offset+type_arr
            cut_final = self.r.choice(range(cut_pos1, cut_pos2, type_arr))
            if type_arr == 1:
              result = ''.join([original[:cut_final], original[cut_final+add_size:]])
            elif type_arr == 2:
              if add_size%2 != 0:
                add_size = add_size + 1
              result = ''.join([original[:cut_final], original[cut_final+add_size:]])
            elif type_arr == 4:
              if add_size%4 != 0:
                add_size = add_size + add_size%4
              result = ''.join([original[:cut_final], original[cut_final+add_size:]])
            else:
              if add_size%type_arr != 0:
                add_size = add_size + add_size%type_arr
              result = ''.join([original[:cut_final], original[cut_final+add_size:]])
            return result
        return self.eliminate_random(original, fl)

    def double_eliminate(self, original,fl):
        result=self.eliminate_random_end(original,fl)
        return self.eliminate_random(result,fl)

    def add_random(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos=self.get_cut(size-add_size,fl)
        #right=False
        #while right!=True:
        #    cut_pos = self.r.randint(0, size - add_size)
        #     if cut_pos not in config.MOSTCOMMON:
        #         right = True

        result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos:]])
        #assert len(original) < len(result), "adding failed to increase size  %d %d" % (len(original), len(result))
        return self.change_bytes(result,fl)

    def add_random_string_mutate_2(self, original, fl, arr_sel, add_size):
         start_offset = arr_sel[0]
         end_offset = arr_sel[1]
         type_arr = arr_sel[2]
         #add_pos = self.r.choice(range(start_offset, end_offset, type_arr))
         add_pos = self.get_cut_range(len(original), fl, start_offset, end_offset)
         cut_pos1 = add_pos
         cut_pos2 = add_pos
         if type_arr == 1:
           result = ''.join([original[:cut_pos1], self.random_string(add_size), original[cut_pos2:]])
         elif type_arr == 2:
           if add_size%2 != 0:
             add_size = add_size + 1
           result = ''.join([original[:cut_pos1], self.random_string_16(add_size), original[cut_pos2:]])
         elif type_arr == 4:
           if add_size%4 != 0:
             add_size = add_size + add_size%4
           result = ''.join([original[:cut_pos1], self.random_string_32(add_size), original[cut_pos2:]])
         else:
           if add_size%type_arr != 0:
             add_size = add_size + add_size%type_arr
           result = ''.join([original[:cut_pos1], self.random_string(add_size), original[cut_pos2:]])
         return result

    def add_random_string_mutate(self, original, fl, arr_sel, string_add):
         start_offset = arr_sel[0]
         end_offset = arr_sel[1]
         type_arr = arr_sel[2]
         if random.randint(0,9) > 3:
           add_size = max(1, self.r.randint(1, ((end_offset-start_offset)/type_arr) + 1))
         else:
           if arr_sel[3] != -1:
             add_size = -1*arr_sel[3]
           else:
             add_size = self.r.choice(range(((end_offset-start_offset)/type_arr)/2,(end_offset-start_offset)/type_arr))
         #add_pos = self.r.choice(range(start_offset, end_offset, type_arr))
         add_pos = self.get_cut_range(len(original), fl, start_offset, end_offset)
         cut_pos1 = add_pos
         cut_pos2 = add_pos
         result = ''.join([original[:cut_pos1], string_add, original[cut_pos2:]])
	 return result

    def add_random_string(self, original, fl):
        size = len(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
	    arr=config.ANALYSIS_MAP[fl][1] 
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
	    arr=config.ANALYSIS_MAP[tfl][1] 
          
        if len(arr) > 0 and random.randint(0,9) > 3:
            arr_sel = self.r.choice(arr)
            start_offset = arr_sel[0]
	    end_offset = arr_sel[1]
	    type_arr = arr_sel[2]
            if random.randint(0,9) > 3:
              add_size = max(1, self.r.randint(1, ((end_offset-start_offset)/type_arr) + 1))
            else:
              if arr_sel[3] != -1:
                add_size = -1*arr_sel[3]
              else:
                add_size = self.r.choice(range(((end_offset-start_offset)/type_arr)/2,(end_offset-start_offset)/type_arr))
	    #add_pos = self.r.choice(range(start_offset, end_offset, type_arr))
	    add_pos = self.get_cut_range(len(original), fl, start_offset, end_offset)
	    cut_pos1 = add_pos
	    cut_pos2 = add_pos
            if type_arr == 1:
	      result = ''.join([original[:cut_pos1], self.random_string(add_size), original[cut_pos2:]])
            elif type_arr == 2:
              if add_size%2 != 0:
	        add_size = add_size + 1
	      result = ''.join([original[:cut_pos1], self.random_string_16(add_size), original[cut_pos2:]])
            elif type_arr == 4: 
              if add_size%4 != 0:
	        add_size = add_size + add_size%4
	      result = ''.join([original[:cut_pos1], self.random_string_32(add_size), original[cut_pos2:]])
            else:
              if add_size%type_arr != 0:
	        add_size = add_size + add_size%type_arr
	      result = ''.join([original[:cut_pos1], self.random_string(add_size), original[cut_pos2:]])
	    #print 'add_random_string',arr_sel,start_offset,end_offset,type_arr,add_size,cut_pos1,':'.join(x.encode('hex') for x in original[start_offset:end_offset]),':'.join(x.encode('hex') for x in result[start_offset:end_offset]) 
	    return result
        return self.add_random(original, fl)

    def change_random(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.get_cut(size - add_size,fl)
        result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos + add_size:]])
        #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
        return self.change_bytes(result,fl)

    def change_random_string(self, original, fl):
        size = len(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
	    arr=config.ANALYSIS_MAP[fl][1] 
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
	    arr=config.ANALYSIS_MAP[tfl][1] 
          
        if len(arr) > 0 and random.randint(0, 9) > 3:
            arr_sel = self.r.choice(arr)
            start_offset = arr_sel[0]
	    end_offset = arr_sel[1]
	    type_arr = arr_sel[2]
	    add_size = max(1, self.r.randint(1, ((end_offset-start_offset)/type_arr) + 1))
	    cut_pos1 = start_offset
	    cut_pos2 = end_offset+type_arr
	    cut_final = self.get_cut_range(len(original), fl, start_offset, end_offset)
	    #cut_final = self.r.choice(range(cut_pos1, cut_pos2, type_arr))
            if type_arr == 1:
	      result = ''.join([original[:cut_final], self.random_string(add_size), original[cut_final+add_size:]])
            elif type_arr == 2:
              if add_size%2 != 0:
	        add_size = add_size + 1
	      result = ''.join([original[:cut_final], self.random_string_16(add_size), original[cut_final+add_size:]])
            elif type_arr == 4: 
              if add_size%4 != 0:
	        add_size = add_size + add_size%4
	      result = ''.join([original[:cut_final], self.random_string_32(add_size), original[cut_final+add_size:]])
            else:
              if add_size%type_arr != 0:
	        add_size = add_size + add_size%type_arr
	      result = ''.join([original[:cut_final], self.random_string(add_size), original[cut_final+add_size:]])
	    return result
        return self.change_random(original, fl)

    def change_bytes(self,original,fl):
        if len(config.TAINTMAP)==0:
            return original
        lorig=list(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
	    offs=config.ANALYSIS_MAP[fl][2] 
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
	    offs=config.ANALYSIS_MAP[tfl][2]
        #tset=set(offs.keys())-set(config.MOSTCOMMON)
        tset=set(tof)-set(config.MOSTCOMMON)
	#print 'in change_butes', ':'.join(x.encode('hex') for x in lorig)
        if len(tset)>0 and random.randint(0,9)>3:
            cset=self.r.sample(tset,max(1,len(tset)/4))
            result=''.join([e for e in lorig])
            #print offs,cset
            for of in cset:
		if of not in offs.keys():
			continue
                if int(of)+int(offs[of])>len(result) or int(of) < -len(lorig):
                    continue
                if int(offs[of]) == 1:
		  if random.randint(0,9) > 3:
                    if random.randint(0,1) == 0:
                      fuzzed=result[:int(of)]+chr(255-ord(result[int(of)]))+result[int(of)+1:]
                    else:
                      fuzzed=result[:int(of)]+self.r.choice(self.ALL_CHARS)+result[int(of)+1:]
		  else:
                    fuzzed=result[:int(of)]+self.r.choice(self.interesting_8)+result[int(of)+1:]
		  result=fuzzed
                elif int(offs[of]) == 2:
                  if random.randint(0,9) > 3:
		      v = self.r.choice(self.TWO_BYTES)
                      fuzzed=result[:int(of)]+v+result[int(of)+2:] 
                  else:
		    fuzz=list(result)
		    if len(fuzz) < of + offs[of]:
			continue
		    if random.randint(0,1) == 1:
                      for i in range(of,of+offs[of]):
			k = random.randint(-10,10)
                        if (ord(fuzz[i]))%256 != 0xFF:
                          fuzz[i] = chr((ord(fuzz[i])+k)%256)
                          break
                        else:
                          fuzz[i]='\x00'
                    else:
                      for i in range(of+offs[of]-1,of-1,-1):
                        if ord(fuzz[i]) != 0xFF:
                          fuzz[i] = chr((ord(fuzz[i])+1)%256)
                          break
                        else:
                          fuzz[i]='\x00'
                    fuzzed=''.join(x for x in fuzz)
		  result=fuzzed
		  #print result[of].encode('hex'), result[of+1].encode('hex'),':'.join(x.encode('hex') for x in result[of:of+offs[of]])
		elif int(offs[of]) == 4:
                  if random.randint(0,9) <= 4:
                      fuzzed=result[:int(of)]+format(random.randint(0,0xFFFFFFFF), '#010x')[2:].decode('hex')+result[int(of)+4:]
                  else:
		    fuzz=list(result)
		    if len(fuzz) < of + offs[of]:
			continue
		    if random.randint(0,1) == 1:
                      for i in range(of,of+offs[of]):
			k = random.randint(-10,10)
                        if (ord(fuzz[i])+k)%256 != 0xFF:
                          fuzz[i] = chr((ord(fuzz[i])+k)%256)
                          break
                        else:
                          fuzz[i]='\x00'
                    else:
                      for i in range(of+offs[of]-1,of-1,-1):
                        if ord(fuzz[i]) != 0xFF:
                          fuzz[i] = chr((ord(fuzz[i])+1)%256)
                          break
                        else:
                          fuzz[i]='\x00'
                    fuzzed=''.join(x for x in fuzz)
		  result=fuzzed
		elif int(offs[of]) == 16:
		  if random.randint(0,9) >= 3:
		    fuzzed=result[:of]+result[of+random.randint(0,16):]
  		  else:
                    fuzzed=result[:of]+''.join(random.choice(self.ALL_CHARS) for i in range(16))+result[of:]
		  result=fuzzed
		else:
                  fuzzed=result[:of]+''.join(random.choice(self.ALL_CHARS) for i in range(int(offs[of])))+result[of:]
		  result=fuzzed

                #raw_input("press enter...")
            return result
	else:
          tset=set(tof)-set(config.MOSTCOMMON)
          if len(tset)>0:
            cset=self.r.sample(tset,max(1,len(tset)/4))
            for of in cset:
                if of>len(lorig)-1 or of < -len(lorig):
                    continue
                lorig[of]=self.r.choice(self.ALL_CHARS)
            result=''.join([e for e in lorig])
            return result
          print "[*] 0 offset set"
          return original
        print "[*] 0 offset set"
        return original

    def increase_by_one(self,original,fl):
        if len(config.TAINTMAP)==0:
            return original
        lorig=list(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
            offs=config.ANALYSIS_MAP[fl][2]
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
            offs=config.ANALYSIS_MAP[tfl][2]
        tset=set(offs.keys())-set(config.MOSTCOMMON)
        if len(tset)>0:
            cset=self.r.sample(tset,max(1,len(tset)/4))
            result=''.join([e for e in lorig])
	    for of in cset:
                if int(of)+int(offs[of])>len(lorig)-1 or int(of) < -len(lorig):
                    continue
		#print ':'.join(x.encode('hex') for x in result[of:of+offs[of]])
		fuzz = list(result)
		if random.randint(0,1) == 1:
	 	  for i in range(of,of+offs[of]):
		    #print ord(fuzz[i]), str(ord(fuzz[i])+1)
		    if ord(fuzz[i]) != 0xFF:
		      fuzz[i] = chr((ord(fuzz[i])+1)%256)
		      break
		    else:
		      fuzz[i]='\x00'
		else:
	 	  for i in range(of+offs[of]-1,of-1,-1):
		    print ord(fuzz[i]), str(ord(fuzz[i])+1)
		    if ord(fuzz[i]) != 0xFF:
		      fuzz[i] = chr((ord(fuzz[i])+1)%256)
		      break
		    else:
		      fuzz[i]='\x00'
                result=''.join([e for e in fuzz])
	        #raw_input("press enter..");
	    return result
	else:
	  return self.raise_single_random(original, fl)

    def decrease_by_one(self,original,fl):
        if len(config.TAINTMAP)==0:
            return original
        lorig=list(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
            offs=config.ANALYSIS_MAP[fl][2]
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
            offs=config.ANALYSIS_MAP[tfl][2]
        tset=set(offs.keys())-set(config.MOSTCOMMON)
        if len(tset)>0:
            cset=self.r.sample(tset,max(1,len(tset)/4))
            result=''.join([e for e in lorig])
	    for of in cset:
                if int(of)+int(offs[of])>len(lorig)-1 or int(of) < -len(lorig):
                    continue
		#print ':'.join(x.encode('hex') for x in result[of:of+offs[of]])
		fuzz = list(result)
		if random.randint(0,1) == 1:
	 	  for i in range(of,of+offs[of]):
		    if ord(fuzz[i]) != 0x00:
		      fuzz[i] = chr((ord(fuzz[i])-1)%256)
		      break
		    else:
		      fuzz[i]='\xFF'
		else:
	 	  for i in range(of+offs[of]-1,of-1,-1):
		    if ord(fuzz[i]) != 0x00:
		      fuzz[i] = chr((ord(fuzz[i])-1)%256)
		      break
		    else:
		      fuzz[i]='\xFF'
                result=''.join([e for e in fuzz])
	        #raw_input("press enter..");
	    return result
	else:
	  return self.lower_single_random(original, fl)
        
    def change_random_full(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(0, size - add_size)
        if len(self.full)>1:
            #result = ''.join([original[:cut_pos], self.r.choice(self.full), original[cut_pos:]])
            result = ''.join([original[:cut_pos], self.random_string(add_size,[self.full]), original[cut_pos:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        elif len(self.obytes)>2 and size >3:
            pos=self.r.sample([k for k in xrange(1,size-1)],2)
            result = ''.join([original[:pos[0]], self.r.choice(self.obytes),original[pos[0]:pos[1]],self.r.choice(self.obytes), original[pos[1]:]])
        #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        else:
            result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos + add_size:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
        return result
  
    def single_change_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            original = ''.join([original[:cut_pos - 1], chr(self.r.randint(1, 255)), original[cut_pos:]])
            #original = ''.join([original[:cut_pos - 1], self.r.choice(self.bytes), original[cut_pos:]])
        #assert len(original) == size, "size changed on a random tweak %d %d" % (len(original), size)
        return original
  
    def lower_single_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        result = original
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            result = ''.join([result[:cut_pos - 1], chr(max(0, ord(result[cut_pos - 1]) - 1)), result[cut_pos:]])
        #assert len(result) == size, "size changed on a random tweak %d %d" % (len(original), size)
        # assert result != original, "nothing changed in lower_single_random %d - actually this can happen due to max above" % changes
        return result
      
    def raise_single_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        result = original
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            result = result[:cut_pos - 1] + chr(min(255, ord(result[cut_pos - 1]) + 1)) + result[cut_pos:]
        #assert len(result) == size, "size changed on a random tweak %d %d" % (len(original), size)
        #assert result != original, "nothing changed in lower_single_random %d - actually this can happen due to min above" % changes
        return result
  
    def eliminate_null(self, original, fl,replacement = 'A'):
        size = len(original)
        cut_pos = original.find('\0', self.r.randint(0, size))
        if (cut_pos != -1):
            result = ''.join([original[:cut_pos], replacement, original[cut_pos + 1:]])
        else:
            return original
        #assert len(original) == len(result), "size changed on a null elmination change %d %d" % (len(original), len(result))
        return result
 
    def eliminate_double_null(self, original, fl,replacement = 'AA'):
        size = len(original) - 1
        cut_pos = original.find('\0\0', self.r.randint(0, size))
        if (cut_pos != -1):
            result = ''.join([original[:cut_pos], replacement, original[cut_pos + 2:]])
        else:
            return original
        #assert len(original) == len(result), "size changed on a null elmination change %d %d" % (len(original), len(result))
        return result
  
    def totally_random(self, original,fl):
        size = len(original)
        return self.random_string(self.r.randint(100, 1000))
       # return ''.join([self.r.choice(self.r.choice(self.allStrings+self.full)) for n in xrange(size)])

    def int_slide(self, original,fl):
        size = len(original)
        value = self.r.choice(['\xFF\xFF\xFF\xFF', '\x80\x00\x00\x00', '\x00\x00\x00\x00'])#, '\xAA\xAA\xAA\xAA', '\x41\x41\x41\x41'])
        if size < 4 : return value[:size]
        start = self.int_slide_position % size
        if start > size - 4: 
            result = original[:start] + value
        else:
            result = ''.join([original[:start], value, original[start + 4:]])
        self.int_slide_position += self.slide_step
        return result

    def double_fuzz(self, original,fl):
        """ runs two fuzzers (one or more of which could be double_fuzz itself! """
        result = self.r.choice(self.mutators)(self, original,fl)
        return self.r.choice(self.mutators)(self, result,fl)

    def double_full_mutate(self,original,fl):
        ''' This is called to do heavy mutation when no progress is made in previous generations. '''
        result = self.change_random_full(original,fl)
        return self.change_random_full(result,fl)
  
    def single_crossover(self, original1, original2):
        """ This function computes single-point crossover on two parents and returns two children.
"""
        point=self.r.uniform(0.1,0.6)
        cut1=int(point*len(original1))
        cut2=int(point*len(original2))
        child1=original1[:cut1]+original2[cut2:]
        child2=original2[:cut2]+original1[cut1:]
        return child1, child2
  
    def double_crossover(self, original1, original2):
        """This function computes 2-point crossover on two parents and returns two children.
"""
        point1=self.r.uniform(0.1,0.3)
        point2=self.r.uniform(0.6,0.8)
        len1=len(original1)
        len2=len(original2)
        cut11=int(point1*len1)
        cut12=int(point2*len1)
        cut21=int(point1*len2)
        cut22=int(point2*len2)
        child1=original1[:cut11]+original2[cut21:cut22]+original1[cut12:]
        child2=original2[:cut21]+original1[cut11:cut12]+original2[cut22:]
        return child1, child2
    
    crossovers=[single_crossover, double_crossover]

    ##NOTE: we added few mutators more than one so that such operations can be frequent. added ones are: eliminate_random, change_random_full
    mutators = [eliminate_random_string, change_bytes, change_bytes,add_random_string, add_random_string, add_random, change_random_string,single_change_random,change_random_string, lower_single_random, raise_single_random, eliminate_null, eliminate_double_null, totally_random, int_slide, double_fuzz,change_random_full,change_random_full,eliminate_random,add_random, change_random,increase_by_one,decrease_by_one]
  
    def mutate(self, original,fl):
        result=self.r.choice(self.mutators)(self, original,fl)
        while len(result)<3:
            result= self.r.choice(self.mutators)(self, original,fl)
        assert len(result)>2, "elimination failed to reduce size %d" % (len(result),)
        return result

    def eliminate(self, original,fl):
        loop=self.r.randint(0,3)
        result = self.r.choice([self.double_eliminate,self.eliminate_random_string, self.eliminate])(original,fl)
        if 4<len(result)<10:
            return result
        else:
            return original
        for i in range(loop):
            temp=result
            result = self.r.choice([self.double_eliminate,self.eliminate_random_string, self.eliminate])(result,fl)
        if len(result)<10:
            return temp
        return result


    def crossover(self, original1, original2):
        minlen=min(len(original1), len(original2))
        if minlen <20:
            return original1, original2 # we don't do any crossover as parents are two young to have babies ;)
        return self.r.choice(self.crossovers)(self, original1,original2)

