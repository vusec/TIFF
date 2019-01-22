/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2012 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "pin.H"
#include "list.h"

#define PTR_LENGTH (sizeof(ADDRINT))

PIN_MUTEX fileLock;

KNOB<std::string> KnobOutPut(KNOB_MODE_WRITEONCE, "pintool", "o", "./trace.log",
	"Output trace file");

typedef struct{
	ADDRINT ip;
	ADDRINT callsite;
	ADDRINT sp;
	BOOL isFunc;
	std::vector<UINT64> ins_vec;
	list_head_t callstack;
	list_head_t blockstack;
}rt_ctx_t;

typedef struct{
	list_head_t rt_callstack;
	list_head_t rt_blockstack;
}thread_ctx_t;

thread_ctx_t threads_ctx[100];

static void PIN_FAST_ANALYSIS_CALL
push_callstack(THREADID tid, ADDRINT ip, ADDRINT sp, ADDRINT callsite)
{
	rt_ctx_t *ctx;

	ctx = new rt_ctx_t();
	ctx->sp = sp;
	ctx->ip = ip;
	ctx->callsite = callsite;
	ctx->isFunc = true;
	list_add(&(ctx->callstack),&threads_ctx[tid].rt_callstack);
	list_add(&(ctx->blockstack),&threads_ctx[tid].rt_blockstack);
}

void 
SplitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
  std::string::size_type pos1, pos2;
  pos2 = s.find(c);
  pos1 = 0;
  while(std::string::npos != pos2)
  {
    v.push_back(s.substr(pos1, pos2-pos1));
 
    pos1 = pos2 + c.size();
    pos2 = s.find(c, pos1);
  }
  if(pos1 != s.length())
    v.push_back(s.substr(pos1));
}

static void PIN_FAST_ANALYSIS_CALL
pop_callstack(THREADID tid, ADDRINT ip, ADDRINT sp, ADDRINT retsite)
{
	rt_ctx_t *ctx,*tmpctx;
	FILE* pfile;
	list_head_t *iter;
	IMG img;
	ADDRINT laddr;
	std::string sname;
	std::vector<std::string> splitted;
	
	sp = sp + PTR_LENGTH;
	list_for_each(iter,&(threads_ctx[tid].rt_callstack)){
		ctx = list_entry(iter, rt_ctx_t, callstack);
		if ((ctx->sp == sp)&&(retsite == ctx->callsite)){
			break;
		}
	}
	if (iter!=&threads_ctx[tid].rt_callstack){
		ctx = list_entry(iter, rt_ctx_t, callstack);
		PIN_LockClient();
		img = IMG_FindByAddress(ctx->ip);
		PIN_UnlockClient();
		if (IMG_Invalid() == img){
			laddr = 0;
			sname = "none";
		}
		else{
			laddr = IMG_LowAddress(img);
			SplitString(IMG_Name(img), splitted, "/");
			if (IMG_IsMainExecutable(img))
				sname = "mainEXE";
			else
				sname = splitted.back();
		}
		if (sname.length() < 5){
			sname = "none";
		}
		PIN_MutexLock(&fileLock);
		pfile = fopen(KnobOutPut.Value().c_str(), "a+");
		if (pfile == NULL){
			PIN_MutexUnlock(&fileLock);
			return;
		}
		fprintf(pfile,"Function : %lx,%s\n",ctx->ip - laddr,sname.c_str());
		for (iter = threads_ctx[tid].rt_blockstack.next; iter!=&(ctx->blockstack);)
		{
			tmpctx = list_entry(iter,rt_ctx_t,blockstack);
			iter = iter->next;
			if (tmpctx->isFunc)
			{
				while (!tmpctx->ins_vec.empty()){
					fprintf(pfile, "%lx,",tmpctx->ins_vec.back() - laddr);
					tmpctx->ins_vec.pop_back();
				}
				list_del(&(tmpctx->callstack));
			}
			else{
				while (!tmpctx->ins_vec.empty()){
					fprintf(pfile, "%lx,",tmpctx->ins_vec.back() - laddr);
					tmpctx->ins_vec.pop_back();
				}
			}
			list_del(&(tmpctx->blockstack));
			free(tmpctx);
		}
		while (!ctx->ins_vec.empty()){
			fprintf(pfile, "%lx,",ctx->ins_vec.back() - laddr);
			ctx->ins_vec.pop_back();
		}
		list_del(&(ctx->callstack));
		list_del(&(ctx->blockstack));
		free(ctx);
		fprintf(pfile,"\n");
		fclose(pfile);
		PIN_MutexUnlock(&fileLock);
	}
}

static void PIN_FAST_ANALYSIS_CALL
push_blockstack(THREADID tid, BOOL taken, ADDRINT branch, ADDRINT falls)
{
	rt_ctx_t *ctx;

	ctx = new rt_ctx_t();
	ctx->sp = 0;
	ctx->ip = (taken)?branch:falls;
	ctx->callsite = 0;
	ctx->isFunc = false;
	ctx->callstack.prev = NULL;
	ctx->callstack.next = NULL;
	list_add(&(ctx->blockstack),&threads_ctx[tid].rt_blockstack);
}

static void PIN_FAST_ANALYSIS_CALL
push_ins(THREADID tid, ADDRINT ip)
{
	rt_ctx_t *ctx;

	if (!list_empty(&(threads_ctx[tid].rt_blockstack))){
		ctx = list_entry(threads_ctx[tid].rt_blockstack.next, rt_ctx_t, blockstack);
		ctx->ins_vec.push_back(ip);
	}
}


static void
trace_inspect(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl);INS_Valid(ins);ins = INS_Next(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(push_ins),		
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_INST_PTR,
				IARG_END);
			OPCODE vOPCode = INS_Opcode(ins);
			if (INS_IsCall(ins)){
			//	LOG(INS_Disassemble(ins) + "\n");
				if((vOPCode == XED_ICLASS_CALL_FAR)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(push_callstack),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_INST_PTR,
						IARG_REG_VALUE, REG_RSP,
						IARG_ADDRINT, INS_Address(ins)+INS_Size(ins),
						IARG_END);
				}else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(push_callstack),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_BRANCH_TARGET_ADDR,
						IARG_REG_VALUE, REG_RSP,
						IARG_ADDRINT, INS_Address(ins)+INS_Size(ins),
						IARG_END);
				
				}
			}
			else if (INS_IsRet(ins)){
			//	LOG(INS_Disassemble(ins) + "\n");
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(pop_callstack),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_INST_PTR,
					IARG_REG_VALUE, REG_RSP,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			}
			else if (INS_IsBranch(ins)){
				if(!INS_IsXend(ins) && !INS_IsXbegin(ins)){
				/* traverse all the instructions in the BBL */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(push_blockstack),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_BRANCH_TAKEN,
						IARG_BRANCH_TARGET_ADDR,
						IARG_FALLTHROUGH_ADDR,
						IARG_END);
				}
			}
		}
	}
}


// This function is called when the application exits
// It closes the output file.
VOID finish(INT32 code, VOID *v)
{
	//rt_ctx_t *ctx,*tmpctx;
	//list_head_t *iter;
	
	/*list_for_each(iter,&(threads_ctx[tid].rt_callstack)){
		ctx = list_entry(iter, rt_ctx_t, callstack);
		fprintf(pfile,"Function : %lx,0\n",ctx->ip);
	}*/
	PIN_MutexFini(&fileLock);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	std::cerr << "This tool demonstrates the use of extended debugger commands" << endl;
	std::cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
	
	if (KnobOutPut.Value().empty())
		return Usage();
	
	for (int tid=0; tid<100; tid++){
		INIT_LIST_HEAD(&threads_ctx[tid].rt_callstack);
		INIT_LIST_HEAD(&threads_ctx[tid].rt_blockstack);
	}

	PIN_MutexInit(&fileLock);

	
	// Register trace instrument function
	TRACE_AddInstrumentFunction(trace_inspect,NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(finish, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
