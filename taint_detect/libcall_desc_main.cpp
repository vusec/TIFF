#include <string.h>
#include <map>

#include "libcall_desc.h"
#include "tagmap.h"
#include "libdft_api.h"
#include "branch_pred.h"
#include "libdft_utils.h"
#include "libdft_log.h"
#include "heap_desc.h"
#include <assert.h>
#include "pin.H"


extern thread_ctx_t *threads_ctx;
extern int flag;
extern std::map<UINT256_T, bool> to_store_heap;


static void post_malloc_hook(libcall_ctx_t*);
static void pre_free_hook(libcall_ctx_t*);

static void post_strcpy_hook(libcall_ctx_t*);
static void post_strncpy_hook(libcall_ctx_t*);
/* libcall descriptors */
libcall_desc_t libcall_desc[LIBCALL_MAX] = {
	/* malloc, libc */
	{"malloc", "libc.so.6", 0, 1, NULL, post_malloc_hook},
	/* calloc, libc */
	{"calloc", "libc.so.6", 0, 2, NULL, NULL},
	/* realloc, libc */
	{"realloc", "libc.so.6", 0, 2, NULL, NULL},
	/* free, libc */
	{"free", "libc.so.6", 0, 1, pre_free_hook, NULL}
	/* strcpy, libc */
//	{"strcpy", "libc.so.6", 0, 2, NULL, post_strcpy_hook}, 
	/* strncpy, libc */
//	{"strncpy", "libc.so.6", 0, 3, NULL, post_strncpy_hook}, 
};

/* heap manage */
extern PIN_MUTEX HeapLock;
extern heap_desc_map_t heap_desc_map;
extern heap_ctx_map_t heap_ctx_map;

/*
 * add a new pre-libcall callback into a libcall descriptor
 *
 * @desc:	the libcall descriptor
 * @pre:	function pointer to the pre-libcall handler
 *
 * returns:	0 on success, 1 on error
 */
int
libcall_set_pre(libcall_desc_t *desc, void (* pre)(libcall_ctx_t*))
{
	/* sanity checks */
	if (unlikely((desc == NULL) | (pre == NULL)))
		/* return with failure */
		return 1;

	/* update the pre-libcall callback */
	desc->pre = pre;

	/* success */
	return 0;
}

/*
 * add a new post-libcall callback into a libcall descriptor
 *
 * @desc:	the libcall descriptor
 * @pre:	function pointer to the post-libcall handler
 *
 * returns:	0 on success, 1 on error
 */
int
libcall_set_post(libcall_desc_t *desc, void (* post)(libcall_ctx_t*))
{
	/* sanity checks */
	if (unlikely((desc == NULL) | (post == NULL)))
		/* return with failure */
		return 1;

	/* update the post-libcall callback */
	desc->post = post;

	/* success */
	return 0;
}

/*
 * remove the pre-libcall callback from a libcall descriptor
 *
 * @desc:       the libcall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int
libcall_clr_pre(libcall_desc_t *desc)
{
	/* sanity check */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the pre-libcall callback */
	desc->pre = NULL;

	/* return with success */
	return 0;
}

/*
 * remove the post-libcall callback from a libcall descriptor
 *
 * @desc:       the libcall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int
libcall_clr_post(libcall_desc_t *desc)
{
	/* sanity check */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the post-libcall callback */
	desc->post = NULL;
	
	/* return with success */
	return 0;
}

static void PIN_FAST_ANALYSIS_CALL
libenter_save(THREADID tid, CONTEXT* ctxt, ADDRINT ip, uint32_t index, ADDRINT return_ip)
{
	ADDRINT esp;
	int i;

	threads_ctx[tid].libcall_ctx.nr = (int)index;
	threads_ctx[tid].libcall_ctx.tid = tid;
	threads_ctx[tid].libcall_ctx.ip = ip;
	threads_ctx[tid].libcall_ctx.arg = (ADDRINT*)malloc(sizeof(ADDRINT)*std::max(libcall_desc[index].nargs,6));

	if (threads_ctx[tid].libcall_ctx.arg == NULL)
		exit(1);

	threads_ctx[tid].libcall_ctx.arg[0] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RDI);
	threads_ctx[tid].libcall_ctx.arg[1] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RSI);
	threads_ctx[tid].libcall_ctx.arg[2] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RDX);
	threads_ctx[tid].libcall_ctx.arg[3] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_RCX);
	threads_ctx[tid].libcall_ctx.arg[4] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_R8);
	threads_ctx[tid].libcall_ctx.arg[5] = PIN_GetContextReg(ctxt, LEVEL_BASE::REG_R9);
	//LOG("enter " + StringFromAddrint(threads_ctx[tid].libcall_ctx.arg[0]) + " " + StringFromAddrint(threads_ctx[tid].libcall_ctx.ip) + "\n");
	esp = PIN_GetContextReg(ctxt,LEVEL_BASE::REG_RSP);
	for (i=0;i<libcall_desc[index].nargs-6;i++){
		LOG("Should not be here " + decstr(libcall_desc[index].nargs) + " " + decstr(index) + "\n");
		/* not safe, the arguments can not be 32-bit long */
		PIN_SafeCopy(&threads_ctx[tid].libcall_ctx.arg[i],(void*)(esp+(i+1)*(sizeof(ADDRINT)/sizeof(char))),sizeof(ADDRINT));
	}
	threads_ctx[tid].libcall_ctx.exit = return_ip;
	if (unlikely(libcall_desc[index].pre != NULL))
		libcall_desc[index].pre(&threads_ctx[tid].libcall_ctx);
}

static void PIN_FAST_ANALYSIS_CALL
libexit_save(THREADID tid, CONTEXT* ctxt, ADDRINT ip)
{
	/*if (likely(ip != threads_ctx[tid].libcall_ctx.exit))
		return;*/
	
	int index = threads_ctx[tid].libcall_ctx.nr;
	
	threads_ctx[tid].libcall_ctx.exit = 0;
	threads_ctx[tid].libcall_ctx.ret = PIN_GetContextReg(ctxt,LEVEL_BASE::REG_RAX);
	if (unlikely(libcall_desc[index].post != NULL))
		libcall_desc[index].post(&threads_ctx[tid].libcall_ctx);
	if (libcall_desc[index].nargs>0 && threads_ctx[tid].libcall_ctx.arg != NULL){
		free(threads_ctx[tid].libcall_ctx.arg);
		threads_ctx[tid].libcall_ctx.arg = NULL;
	}
}

VOID libcall_img_inspect(IMG img, VOID *v)
{

	string img_name;
	img_name = IMG_Name(img);
//	RTN rtn1 = RTN_FindByName(img, "strcpy");

/*	if(RTN_Valid(rtn1)){
		LOG("Found\n");
	}
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // RTN_InsertCall() and INS_InsertCall() are executed in order of
        // appearance.  In the code sequence below, the IPOINT_AFTER is
        // executed before the IPOINT_BEFORE.
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
		LOG(img_name + " " + RTN_Name(rtn) + "\n");
        }
    }*/

	RTN rtn;
	unsigned int pos;

	for (int i=0;i<LIBCALL_MAX;i++){
		pos = img_name.rfind(libcall_desc[i].lib);
		if ((pos!=string::npos)&&(img_name.length()-pos == strlen(libcall_desc[LIBCALL_LIBC].lib))){
			rtn = RTN_FindByName(img, libcall_desc[i].name);
			if (RTN_Valid(rtn)){
				RTN_Open(rtn);
				RTN_InsertCall(rtn,
						IPOINT_BEFORE,
						AFUNPTR(libenter_save),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_UINT32,i,
						IARG_RETURN_IP,
						IARG_END);
				RTN_InsertCall(rtn,
						IPOINT_AFTER,
						AFUNPTR(libexit_save),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_END);
				RTN_Close(rtn);

			}
		}
	}
}


VOID libcall_trace_inspect(TRACE trace, VOID *v)
{
}


static void post_strcpy_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->arg[0] == ctx->ret){
		tag_t tsrc = file_tagmap_getb(ctx->arg[1]);
		tag_t tdest = file_tagmap_getb(ctx->arg[0]);
		LOG(tag_sprint(tsrc) + " "  + tag_sprint(tdest) + "\n");
		LOG(StringFromAddrint(ctx->arg[0]) + " " + StringFromAddrint(ctx->arg[1]) + " " + StringFromAddrint(ctx->ret) + "\n");
	}
}

static void post_strncpy_hook(libcall_ctx_t* ctx){
        if(ctx->arg && ctx->arg[0] == ctx->ret){
                tag_t tsrc = file_tagmap_getb(ctx->arg[1]);
                tag_t tdest = file_tagmap_getb(ctx->arg[0]);
		size_t n = (size_t)ctx->arg[2];
                LOG(tag_sprint(tsrc) + " "  + tag_sprint(tdest) + decstr(n) + "\n");
                LOG(StringFromAddrint(ctx->arg[0]) + " " + StringFromAddrint(ctx->arg[1]) + " " + StringFromAddrint(ctx->ret) + "\n");
        }
}


static void post_malloc_hook(libcall_ctx_t* ctx)
{
	heap_ctx_t *heap_ctx;
	TAG_TYPE *ptag;
	heap_desc_t *heap_desc;
	rt_ctx_t *rtctx;
	list_head_t *iter;
//	LOG( StringFromAddrint(ctx->ip) + "\n");	
	if (ctx->ret != 0 && ctx->arg){
		/* malloc successed */
		threads_ctx[ctx->tid].vcpu.gpr[DFT_REG_RAX].isPointer = TRUE;
		threads_ctx[ctx->tid].vcpu.gpr[DFT_REG_RAX].base_addr = ctx->ret;
		heap_ctx = new heap_ctx_t();
		heap_ctx->start = ctx->ret;
		heap_ctx->size = ctx->arg[0];
		getMD5(ctx->tid, &(heap_ctx->md5));
		
		PIN_MutexLock(&HeapLock);
		//need to find the heap desc
		if (heap_desc_map.find(heap_ctx->md5)==heap_desc_map.end()){
			//need to create one
			heap_desc = new heap_desc_t();
			heap_desc->md5 = heap_ctx->md5;
			heap_desc->dtags = NULL;
			heap_desc->dlength = 0;
			list_for_each(iter, &(threads_ctx[ctx->tid].rt_stack_head))
			{
				rtctx = list_entry(iter, rt_ctx_t, rt_stack);
				if (rtctx->type == FUNC_CTX_TYPE){
					heap_desc->callstack.push_back(rtctx->callsite);
				}
			}
			heap_desc_map[heap_ctx->md5] = heap_desc;
			to_store_heap[heap_ctx->md5] = 0;
		}
		heap_desc = heap_desc_map[heap_ctx->md5];
		heap_ctx->pdesc = heap_desc;
		heap_ctx_map[ctx->ret] = heap_ctx;
		load_heap_taint(ctx->ret, ctx->arg[0], heap_desc->dtags, heap_desc->dlength);
		ptag = tagmap_get_ref(ctx->ret);
		//LOG("malloc " + hexstr(heap_desc->md5.d[0]) + " " + StringFromAddrint(ctx->ret) + "\n");
		ptag->base_addr = ctx->ret;
		PIN_MutexUnlock(&HeapLock);
	}
}

static void pre_free_hook(libcall_ctx_t* ctx)
{
	heap_ctx_t *heap_ctx;
	heap_desc_t *heap_desc;
	ADDRINT root;
	
	root = ctx->arg[0];
	PIN_MutexLock(&HeapLock);
	if ((root!=0)&&(heap_ctx_map.find(root)!=heap_ctx_map.end())){
		heap_ctx = heap_ctx_map[root];
		assert(heap_ctx!=NULL);
		heap_desc = heap_ctx->pdesc;
		//LOG("free " + hexstr(heap_desc->md5.d[0]) + " " + StringFromAddrint(root) + "\n");
		store_heap_taint(root, heap_ctx->size, heap_desc);
		heap_ctx_map[root] = NULL;
		heap_ctx_map.erase(root);
		delete heap_ctx;
	}
	PIN_MutexUnlock(&HeapLock);
}

void free_callback()
{
	heap_ctx_map_t::iterator iter;
	heap_ctx_t *heap_ctx;
	heap_desc_t *heap_desc;
	ADDRINT root;
	
	PIN_MutexLock(&HeapLock);
	for (iter = heap_ctx_map.begin(); iter!= heap_ctx_map.end(); iter++){
		root = iter->first;
		heap_ctx = iter->second;
		assert(root !=0);
		heap_desc = heap_ctx->pdesc;
		store_heap_taint(root, heap_ctx->size, heap_desc);
		heap_ctx_map[root] = NULL;
	}
	PIN_MutexUnlock(&HeapLock);
}

