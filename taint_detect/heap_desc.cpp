#include <map>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include "heap_desc.h"
#include "list.h"
#include "libdft_utils.h"
#include "libdft_api.h"
#include "tagmap.h"

#include <map>

#include "pin.H"

extern thread_ctx_t *threads_ctx;
extern std::map<UINT256_T, bool> to_store_heap;

PIN_MUTEX HeapLock;
heap_desc_map_t heap_desc_map;
heap_ctx_map_t heap_ctx_map;

heap_ctx_t* heap_lookup(ADDRINT addr)
{
	heap_ctx_map_t::iterator iter;
	heap_ctx_t* ctx;
	
	for (iter=heap_ctx_map.begin(); iter!=heap_ctx_map.end(); iter++)
	{
		ctx = iter->second;
		if ((addr >= ctx->start)&&(addr<(ctx->start+ctx->size))){
			PIN_MutexUnlock(&HeapLock);
			return ctx;
		}
	}
	return NULL;
}

void load_heap_taint(ADDRINT root, UINT32 size, TAG_TYPE* ptag_src, UINT32 src_len)
{
	UINT32 i, len;

	tagmap_clrn(root, size);
	
	len = (src_len > size)?size:src_len;
	for (i=0; i<len; i++)
	{
		ptag_src[i].base_addr = root + ptag_src[i].base_addr;
		tagmap_setb(root+i, ptag_src[i]);
	}
}

void store_heap_taint(ADDRINT root, UINT32 size, heap_desc_t* heap_desc)
{
	UINT32 i,len;
	TAG_TYPE *ptag, *ptag_dst;

	if (heap_desc->dlength == 0){
		heap_desc->dtags = (TAG_TYPE*)malloc(sizeof(TAG_TYPE)*size);
		len = size;
		heap_desc->dlength = len;
	}
	else{
		len = std::min((heap_desc->dlength), size);
	}
	ptag_dst = heap_desc->dtags;
	bool fl = 0;
	for (i = 0; i<len; i++){
		//LOG(StringFromAddrint(root+ i) + " ");
		ptag = tagmap_get_ref(root+i);
		if(file_tag_testb(root+i)){
                        tag_t t = file_tagmap_getb(root+i);
			int no = t.numberOfOnes();
/*                        if(no <= limit_offset && no > 0){
                                if(ptag_dst[i].istaint >= 1){
                                        std::string s = ptag_dst[i].file_taint->gettaint();
					if(s != tag_sprint(t)){
	                                        s += ":" + tag_sprint(t);
        	                                Taint<std::string>* tstore = new Taint<std::string>(s);
                	                        ptag_dst[i].file_taint = tstore;
                        	                ptag_dst[i].istaint++;
					}

                                }else{
                                	Taint<std::string>* tstore = new Taint<std::string>(tag_sprint(t));
	                                ptag_dst[i].file_taint = tstore;
					ptag_dst[i].istaint = 1;
					fl = 1;		
                                }

                        }else{
				if(ptag_dst[i].istaint == 1){
					fl = 1;
				}else{
	                                Taint<std::string>* tstore = new Taint<std::string>(std::string("{}"));
        	                        ptag_dst[i].file_taint = tstore;
					ptag_dst[i].istaint = 0;
				}
                        }*/
			if(ptag->istaint >= 1){
                                ptag_dst[i].file_taint = ptag->file_taint;
                                ptag_dst[i].istaint = ptag->istaint;
				std::string s = ptag->file_taint->gettaint();
                                std::map<std::string, bool> m = ptag->file_taint->m;
                                if(no <= limit_offset && no > 0 && m.find(tag_sprint(t)) == m.end()){
                                       s += ":" + tag_sprint(t);
                                       Taint<std::string>* tstore = new Taint<std::string>(s);
                                       tstore->m = m;
                                       ptag->file_taint = tstore;
                                       ptag->istaint++;
                                       ptag->file_taint->m[tag_sprint(t)] = 1;
                                }
                                fl = 1;
                        }else{
 //                               tag_t t = file_tagmap_getb(root+i);
   //                             int no = t.numberOfOnes();
                                if(no <= limit_offset && no > 0){
                                        Taint<std::string>* tstore = new Taint<std::string>(tag_sprint(t));
                                        ptag_dst[i].file_taint = tstore;
                                        ptag_dst[i].istaint = 1;
                                        ptag_dst[i].file_taint->m[tag_sprint(t)] = 1;
                                }else{  
                                        Taint<std::string>* tstore = new Taint<std::string>(std::string("{}"));
                                        ptag_dst[i].file_taint = tstore;
                                        ptag_dst[i].istaint = 0;
                                }

                        }
                        //LOG(StringFromAddrint(root+i) + " " + tag_sprint(file_tagmap_getb(root+i)) + "\n");
                }
/*		if(root+i == 0x0000555556089cb0){
			LOG(StringFromAddrint(ptag_dst[i].base_addr) + " " + StringFromAddrint(ptag->base_addr) +  " " + StringFromAddrint(root) + "\n");
		}*/
		ptag_dst[i].dflag |= ptag->dflag;
		if (ptag->isPointer)
			ptag_dst[i].dflag = SET_MASK(ptag_dst[i].dflag, POINTER_MASK);
		if (ptag->size > ptag_dst[i].size)
			ptag_dst[i].size = ptag->size;
		/* select a better base*/
		if ((ptag_dst[i].base_addr == 0)||(ptag_dst[i].base_addr == i))
			ptag_dst[i].base_addr = ptag->base_addr;
		else if ((ptag_dst[i].base_addr > i)&&(ptag->base_addr < (root+i)))
			ptag_dst[i].base_addr = ptag->base_addr;
		else if ((ptag->base_addr < (root + i))&&((root + i - ptag->base_addr) < (i - ptag_dst[i].base_addr)))
			ptag_dst[i].base_addr = ptag->base_addr;

		if (ptag_dst[i].base_addr != 0)
			ptag_dst[i].base_addr -= root;
	}
//	LOG("\n");
	to_store_heap[heap_desc->md5] = fl;
}

void getMD5(THREADID tid, UINT256_T *md5_256)
{
	MD5_CTX mdContext;
	UINT8* md5;
	rt_ctx_t *pctx;
	list_head_t *iter;
	UINT32 len;

	md5 = (UINT8*)malloc(sizeof(unsigned char)*(MD5_DIGEST_LENGTH));
	MD5_Init(&mdContext);
	
	list_for_each(iter, &(threads_ctx[tid].rt_stack_head))
	{
		pctx = list_entry(iter, rt_ctx_t, rt_stack);
		if (pctx->type == FUNC_CTX_TYPE){
			MD5_Update(&mdContext, (UINT8*)(&pctx->callsite), sizeof(ADDRINT));
		}
	}
	MD5_Final(md5, &mdContext);
	len = (MD5_DIGEST_LENGTH*sizeof(unsigned char) < sizeof(UINT256_T))?MD5_DIGEST_LENGTH*sizeof(unsigned char) : sizeof(UINT256_T);
	memcpy(md5_256, md5, len);
}
