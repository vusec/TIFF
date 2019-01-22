#ifndef __HEAP_DESC_H__
#define __HEAP_DESC_H__
#include <map>
#include <vector>
#include "libdft_utils.h"
#include "tagmap.h"
#include "pin.H"

typedef struct {
	UINT256_T md5;
	TAG_TYPE *dtags;
	UINT32 dlength;
	std::vector<ADDRINT> callstack;
} heap_desc_t;

typedef struct{
	ADDRINT start;
	UINT32	size;
	UINT256_T md5;
	heap_desc_t *pdesc;
} heap_ctx_t;

typedef std::map<UINT256_T, heap_desc_t*> heap_desc_map_t;
typedef std::map<ADDRINT, heap_ctx_t*> heap_ctx_map_t;

heap_ctx_t* heap_lookup(ADDRINT );
void getMD5(THREADID tid, UINT256_T *md5_256);
void store_heap_taint(ADDRINT root, UINT32 size, heap_desc_t* heap_desc);
void load_heap_taint(ADDRINT root, UINT32 size, TAG_TYPE* ptag_src, UINT32 src_len);

#endif
