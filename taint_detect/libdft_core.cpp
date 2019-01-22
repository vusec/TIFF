/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <set>
#include <map>
#include <algorithm>

#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "tagmap.h"
#include "branch_pred.h"
#include "libdft_utils.h"
#include "libdft_log.h"
#include "heap_desc.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern ADDRINT EXEC_ENTRY;

extern PIN_MUTEX MergeLock;
extern PIN_MUTEX HeapLock;
extern FILE* fMergeLog;

ADDRINT DEBUG_IP;
rt_ctx_t* TRACK_PFUNC;

/* File Taint */
extern tag_dir_t tag_dir;

extern int flag;
extern int limit_offset;
extern std::map<ADDRINT, bool> to_store;
extern std::map<pair<int,int>, int> file_offsets;

#define RTAG(tid) threads_ctx[tid].vcpu.gpr_file

#define R8TAG(tid, RIDX) \
{RTAG(tid)[(RIDX)][0]}
#define R16TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1]}
#define R32TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3]}
#define R64TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3], RTAG(tid)[(RIDX)][4],  RTAG(tid)[(RIDX)][5], RTAG(tid)[(RIDX)][6], RTAG(tid)[(RIDX)][7]}
#define R128TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3], RTAG(tid)[(RIDX)][4],  RTAG(tid)[(RIDX)][5], RTAG(tid)[(RIDX)][6], RTAG(tid)[(RIDX)][7], RTAG(tid)[(RIDX)][8],RTAG(tid)[(RIDX)][9],RTAG(tid)[(RIDX)][10],RTAG(tid)[(RIDX)][11],RTAG(tid)[(RIDX)][12],RTAG(tid)[(RIDX)][13],RTAG(tid)[(RIDX)][14],RTAG(tid)[(RIDX)][15]}



#define MTAG(ADDR) \
        tag_dir_getb(tag_dir, (ADDR))
#define M8TAG(ADDR) \
{tag_dir_getb(tag_dir, (ADDR))}
#define M16TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1)}      
#define M32TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3)}  
#define M64TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3), MTAG(ADDR+4), MTAG(ADDR+5), MTAG(ADDR+6), MTAG(ADDR+7)}  
#define M128TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3), MTAG(ADDR+4), MTAG(ADDR+5), MTAG(ADDR+6), MTAG(ADDR+7),  MTAG(ADDR+8),  MTAG(ADDR+9), MTAG(ADDR+10), MTAG(ADDR+11),  MTAG(ADDR+12),  MTAG(ADDR+13),  MTAG(ADDR+14), MTAG(ADDR+15)}  


UINT32 get_reg_size(REG reg){
        if(REG_is_xmm(reg)){
                return 16;
        }else if(REG_is_gr64(reg)){
                return 8;
        }else if(REG_is_gr32(reg)){
                return 4;
        }else if(REG_is_gr16(reg)){
                return 2;
        }else{
                return 1;
        }
}


size_t REG_INDX(REG reg)
{
        if (reg == REG_INVALID())
                return GRP_NUM;
        switch (reg) {
                case REG_RDI:
                case REG_EDI:
                case REG_DI:
                case REG_DIL:
                        return DFT_REG_RDI;
                        break;
                case REG_RSI:
                case REG_ESI:
                case REG_SI:
                case REG_SIL:
                        return DFT_REG_RSI;
                        break;
                case REG_RBP:
                case REG_EBP:
                case REG_BP:
                case REG_BPL:
                        return DFT_REG_RBP;
                        break;
                case REG_RSP:
                case REG_ESP:
                case REG_SP:
                case REG_SPL:
                        return DFT_REG_RSP;
                        break;
                case REG_RAX:
                case REG_EAX:
                case REG_AX:
                case REG_AH:
                case REG_AL:
                        return DFT_REG_RAX;
                        break;
                case REG_RBX:
                case REG_EBX:
                case REG_BX:
                case REG_BH:
                case REG_BL:
                        return DFT_REG_RBX;
                        break;
                case REG_RCX:
                case REG_ECX:
                case REG_CX:
                case REG_CH:
                case REG_CL:
                        return DFT_REG_RCX;
                        break;
                case REG_RDX:
                case REG_EDX:
                case REG_DX:
                case REG_DH:
                case REG_DL:
                        return DFT_REG_RDX;
                        break;
                case REG_R8:
                case REG_R8D:
                case REG_R8W:
                case REG_R8B:
                        return DFT_REG_R8;
                        break;
                case REG_R9:
                case REG_R9D:
                case REG_R9W:
                case REG_R9B:
                        return DFT_REG_R9;
                        break;
                case REG_R10:
                case REG_R10D:
                case REG_R10W:
                case REG_R10B:
                        return DFT_REG_R10;
                        break;
                case REG_R11:
                case REG_R11D:
                case REG_R11W:
                case REG_R11B:
                        return DFT_REG_R11;
                        break;
                case REG_R12:
                case REG_R12D:
                case REG_R12W:
                case REG_R12B:
                        return DFT_REG_R12;
                        break;
                case REG_R13:
                case REG_R13D:
                case REG_R13W:
                case REG_R13B:
                        return DFT_REG_R13;
                        break;
                case REG_R14:
                case REG_R14D:
                case REG_R14W:
                case REG_R14B:
                        return DFT_REG_R14;
                        break;
                case REG_R15:
                case REG_R15D:
                case REG_R15W:
                case REG_R15B:
                        return DFT_REG_R15;
                        break;
                case REG_XMM0:
                        return DFT_REG_XMM0;
                        break;
                case REG_XMM1:
                        return DFT_REG_XMM1;
                        break;
                case REG_XMM2:
                        return DFT_REG_XMM2;
                        break;
                case REG_XMM3:
                        return DFT_REG_XMM3;
                        break;
                case REG_XMM4:
                        return DFT_REG_XMM4;
                        break;
                case REG_XMM5:
                        return DFT_REG_XMM5;
                        break;
                case REG_XMM6:
                        return DFT_REG_XMM6;
                        break;
                case REG_XMM7:
                        return DFT_REG_XMM7;
                        break;
                case REG_XMM8:
                        return DFT_REG_XMM8;
                        break;
                case REG_XMM9:
                        return DFT_REG_XMM9;
                        break;
                case REG_XMM10:
                        return DFT_REG_XMM10;
                        break;
                case REG_XMM11:
                        return DFT_REG_XMM11;
                        break;
                case REG_XMM12:
                        return DFT_REG_XMM12;
                        break;
                case REG_XMM13:
                        return DFT_REG_XMM13;
                        break;
                case REG_XMM14:
                        return DFT_REG_XMM14;
                        break;
                case REG_XMM15:
                        return DFT_REG_XMM15;
                        break;
                case REG_MM0:
                case REG_ST0:
                        return DFT_REG_ST0;
                        break;
                case REG_MM1:
                case REG_ST1:
                        return DFT_REG_ST1;
			break;
                case REG_MM2:
                case REG_ST2:
                        return DFT_REG_ST2;
                        break;
                case REG_MM3:
                case REG_ST3:
                        return DFT_REG_ST3;
                        break;
                case REG_MM4:
                case REG_ST4:
                        return DFT_REG_ST4;
                        break;
                case REG_MM5:
                case REG_ST5:
                        return DFT_REG_ST5;
                        break;
                case REG_MM6:
                case REG_ST6:
                        return DFT_REG_ST6;
                        break;
                case REG_MM7:
                case REG_ST7:
                        return DFT_REG_ST7;
                        break;

                default:
                        break;
        }
        /* nothing */
        return GRP_NUM;

}

inline REG VCPU_INDX(size_t indx)
{
        REG reg;

        if ((indx >= 3)&&(indx < GRP_NUM))
                reg = (REG)(indx);
        else
                reg = REG_INVALID();
        return reg;

}


void get_array_mem(ADDRINT addr, int size, std::vector<tag_t> &tag){
        switch (size){
                case 1:{
                               tag_t temp[] = M8TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 2:{
                               tag_t temp[] = M16TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 4:{
                               tag_t temp[] = M32TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 8:{
                               tag_t temp[] = M64TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 16:{
                               tag_t temp[] = M128TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                        }
                default:
                     
return;                                                                                                                                                                                                                                                               
        }
}


void get_array_reg(THREADID tid, uint32_t reg, int size, std::vector<tag_t> &tag){                                                             
        switch (size){
                case 1:{
                               tag_t temp[] = R8TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 2:{
                               tag_t temp[] = R16TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 4:{
                               tag_t temp[] = R32TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 8:{
                               tag_t temp[] = R64TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 16:{
                               tag_t temp[] = R128TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                        }
                default:{
                                return;
                        }
        }
        return;
}

vector<std::string> splitted;
void split( std::string const& original, char separator )
{
        std::string::const_iterator start = original.begin();
        std::string::const_iterator end = original.end();
        std::string::const_iterator next = std::find( start, end, separator );
        while ( next != end ) {
                splitted.push_back( std::string( start, next ) );
                start = next + 1;
                next = std::find( start, end, separator );
        }
        splitted.push_back( std::string( start, next ) );
}
/* Printing Log of CMP */
vector<string> output(21,"{}");
void print_log(){
        splitted.clear();
        for(size_t i=3;i<19;i++){
                split(output[i],',');
                if((int)splitted.size() > limit_offset){
                        splitted.clear();
                        return;
                }
                splitted.clear();
        }
        //LOG("IN PRINT LOG\n");
        for(size_t i=0;i<21;i++){
                out << output[i];
                out << " ";
        }
        out << std::endl;
        out << flush;
}
/* Printing Log of LEA */
vector<string> output_lea(10,"{}");
void print_lea_log(){
        splitted.clear();
        for(size_t i=2;i<10;i++){
                split(output_lea[i],',');
                if((int)splitted.size() > limit_offset){
                        splitted.clear();
                        return;
                }
                splitted.clear();
        }
        //LOG("IN PRINT LOG\n");
        for(size_t i=0;i<10;i++){
                out_lea << output_lea[i];
                out_lea << " ";
        }
        out_lea << std::endl;
        out_lea << flush;
}





static void PIN_FAST_ANALYSIS_CALL
_cdqe(THREADID tid)
{
    tag_t src_tag[] = R64TAG(tid, DFT_REG_RAX);
    RTAG(tid)[DFT_REG_RAX][4] = src_tag[0];
    RTAG(tid)[DFT_REG_RAX][5] = src_tag[1];
    RTAG(tid)[DFT_REG_RAX][6] = src_tag[2];
    RTAG(tid)[DFT_REG_RAX][7] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
_cwde(THREADID tid)
{
    tag_t src_tag[] = R16TAG(tid, DFT_REG_RAX);
    RTAG(tid)[DFT_REG_RAX][2] = src_tag[0];
    RTAG(tid)[DFT_REG_RAX][3] = src_tag[1];
}

/*
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_l(THREADID tid, uint32_t dst, uint32_t src)
{
        tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

    for(size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

    for(size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

    for (size_t i = 0; i < 8; i++)
            threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

    for (size_t i = 0; i < 4; i++)
            threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_low_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t src_high_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

        threads_ctx[tid].vcpu.gpr_file[dst][0] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][1] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][2] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][3] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][4] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][5] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][6] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][7] = src_high_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opql(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);
	

    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tag[i%4];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_low_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t src_high_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_low_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_high_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][2] = src_low_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][3] = src_high_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opwb(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M8TAG(src);
	
	RTAG(tid)[dst][0] = src_tag[0];
	RTAG(tid)[dst][1] = src_tag[0];
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opqb(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = tag_dir_getb(tag_dir, src);
	
    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplb(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = tag_dir_getb(tag_dir, src);
	
    for (size_t i = 0; i < 4; i++)
	    RTAG(tid)[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opqw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tags[] = M16TAG(src);
	
    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opql(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tags[] = M32TAG(src);

    for (size_t i = 0; i < 8; i++)
            RTAG(tid)[dst][i] = src_tags[i%4];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tags[] = M16TAG(src);
	
    for (size_t i = 0; i < 4; i++)
	    RTAG(tid)[dst][i] = src_tags[i%2];
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
    for (size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
    for (size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqw(THREADID tid, uint32_t dst, uint32_t src)
{
	tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

    for(size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
	tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

    for(size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opwb(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = M8TAG(src);
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opqb(THREADID tid, uint32_t dst, ADDRINT src)
{
	tag_t src_tag = tag_dir_getb(tag_dir, src);
	//LOG("movzx byte " + tag_sprint(src_tag) + " " + StringFromAddrint(src) + " " + decstr(dst) + "\n");	
    for (size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplb(THREADID tid, uint32_t dst, ADDRINT src)
{
	tag_t src_tag = tag_dir_getb(tag_dir, src);
	//LOG("movzx byte " + tag_sprint(src_tag) + " " + StringFromAddrint(src) + " " + decstr(dst) + "\n");	
    for (size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opqw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};

    for( size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};

    for( size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}
*/
static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opq_fast(THREADID tid, uint32_t dst_val, uint32_t src,
							uint32_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R64TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

	/* update */
    tag_t src_tags[] = R64TAG(tid, src);

    for (size_t i = 0; i < 8; i++){
        RTAG(tid)[DFT_REG_RAX][i] = src_tags[i];
    }
	/* compare the dst and src values */
	return (dst_val == src_val);
}


static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_fast(THREADID tid, uint32_t dst_val, uint32_t src,
							uint32_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R32TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

	/* update */
    tag_t src_tags[] = R32TAG(tid, src);

    for (size_t i = 0; i < 4; i++){
        RTAG(tid)[DFT_REG_RAX][i] = src_tags[i];
    }
	/* compare the dst and src values */
	return (dst_val == src_val);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opq_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3],
			  threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][4], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][5], 
			 threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][6], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][7]};
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1],
                        threads_ctx[tid].vcpu.gpr_file[src][2], threads_ctx[tid].vcpu.gpr_file[src][3],
			threads_ctx[tid].vcpu.gpr_file[src][4],	threads_ctx[tid].vcpu.gpr_file[src][5],
			threads_ctx[tid].vcpu.gpr_file[src][6], threads_ctx[tid].vcpu.gpr_file[src][7]};
    for (size_t i = 0; i < 8; i++){
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i];
    }
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1],
                            threads_ctx[tid].vcpu.gpr_file[src][2], threads_ctx[tid].vcpu.gpr_file[src][3]};
    for (size_t i = 0; i < 4; i++){
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i];
    }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_fast(THREADID tid, uint16_t dst_val, uint32_t src,
						uint16_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R32TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = R16TAG(tid, src);
    RTAG(tid)[DFT_REG_RAX][0] = src_tags[0];
    RTAG(tid)[DFT_REG_RAX][1] = src_tags[1];

	/* compare the dst and src values */
	return (dst_val == src_val);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */

    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tags[0];
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tags[1];
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opq_fast(THREADID tid, uint32_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][4],
	threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][5], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][6], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][7]};
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1),
        tag_dir_getb(tag_dir, src+2), tag_dir_getb(tag_dir, src+3), tag_dir_getb(tag_dir, src+4),
	tag_dir_getb(tag_dir, src+5), tag_dir_getb(tag_dir, src+6), tag_dir_getb(tag_dir, src+7)};
    for (size_t i = 0; i < 8; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
     }

	return (dst_val == *(uint32_t *)src);
}


static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opl_fast(THREADID tid, uint32_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1),
        tag_dir_getb(tag_dir, src+2), tag_dir_getb(tag_dir, src+3)};
    for (size_t i = 0; i < 4; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
     }

	return (dst_val == *(uint32_t *)src);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opq_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t saved_tags[] = R64TAG(tid, DFT_REG_HELPER1);
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = R64TAG(tid, src);
    for (size_t i = 0; i < 8; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opl_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t saved_tags[] = R32TAG(tid, DFT_REG_HELPER1);
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = R32TAG(tid, src);
    for (size_t i = 0; i < 4; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opw_fast(THREADID tid, uint16_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3]};

    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};
    for (size_t i = 0; i < 2; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
    }
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(uint16_t *)src);
}

static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opw_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};

    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};
    for (size_t i = 0; i < 2; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t dst_tag[] = R16TAG(tid, dst);
    
    tag_t src_tag[] = R16TAG(tid, src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[src][0] = dst_tag[0];
    RTAG(tid)[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag = RTAG(tid)[dst][1];
    
    tag_t src_tag = M8TAG(src);

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    tag_dir_setb(tag_dir, src, tmp_tag);
}
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag = RTAG(tid)[dst][0];
    
    tag_t src_tag = M8TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag;
    tag_dir_setb(tag_dir, src, tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R16TAG(tid, dst);
    
    tag_t src_tag[] = M16TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R64TAG(tid, dst);
    tag_t src_tag[] = M64TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[dst][2] = src_tag[2];
    RTAG(tid)[dst][3] = src_tag[3];
    RTAG(tid)[dst][4] = src_tag[4];
    RTAG(tid)[dst][5] = src_tag[5];
    RTAG(tid)[dst][6] = src_tag[6];
    RTAG(tid)[dst][7] = src_tag[7];

    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
    tag_dir_setb(tag_dir, src+2, tmp_tag[2]);
    tag_dir_setb(tag_dir, src+3, tmp_tag[3]);
    tag_dir_setb(tag_dir, src+4, tmp_tag[4]);
    tag_dir_setb(tag_dir, src+5, tmp_tag[5]);
    tag_dir_setb(tag_dir, src+6, tmp_tag[6]);
    tag_dir_setb(tag_dir, src+7, tmp_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R32TAG(tid, dst);
    tag_t src_tag[] = M32TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[dst][2] = src_tag[2];
    RTAG(tid)[dst][3] = src_tag[3];

    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
    tag_dir_setb(tag_dir, src+2, tmp_tag[2]);
    tag_dir_setb(tag_dir, src+3, tmp_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][1], threads_ctx[tid].vcpu.gpr_file[src][0]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[src][1]);
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][1], threads_ctx[tid].vcpu.gpr_file[src][1]);
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[src][0]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opw(THREADID tid, uint32_t dst, uint32_t src)
{

    tag_t dst_tag[] = {threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[dst][1]};
    tag_t src_tag[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opb_u(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
    tag_t dst_tag = tag_dir_getb(tag_dir, dst);

    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag;
    tag_dir_setb(tag_dir, src, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opb_l(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t dst_tag = tag_dir_getb(tag_dir, dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag;
    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opw(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = M16TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opq(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = M64TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
    threads_ctx[tid].vcpu.gpr_file[src][2] = dst_tag[2];
    threads_ctx[tid].vcpu.gpr_file[src][3] = dst_tag[3];
    threads_ctx[tid].vcpu.gpr_file[src][4] = dst_tag[4];
    threads_ctx[tid].vcpu.gpr_file[src][5] = dst_tag[5];
    threads_ctx[tid].vcpu.gpr_file[src][6] = dst_tag[6];
    threads_ctx[tid].vcpu.gpr_file[src][7] = dst_tag[7];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
    tag_dir_setb(tag_dir, dst+2, tag_combine(dst_tag[2], src_tag[2]));
    tag_dir_setb(tag_dir, dst+3, tag_combine(dst_tag[3], src_tag[3]));
    tag_dir_setb(tag_dir, dst+4, tag_combine(dst_tag[4], src_tag[4]));
    tag_dir_setb(tag_dir, dst+5, tag_combine(dst_tag[5], src_tag[5]));
    tag_dir_setb(tag_dir, dst+6, tag_combine(dst_tag[6], src_tag[6]));
    tag_dir_setb(tag_dir, dst+7, tag_combine(dst_tag[7], src_tag[7]));
}


static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opl(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = M32TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
    threads_ctx[tid].vcpu.gpr_file[src][2] = dst_tag[2];
    threads_ctx[tid].vcpu.gpr_file[src][3] = dst_tag[3];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
    tag_dir_setb(tag_dir, dst+2, tag_combine(dst_tag[2], src_tag[2]));
    tag_dir_setb(tag_dir, dst+3, tag_combine(dst_tag[3], src_tag[3]));

}

static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opw(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R16TAG(tid, base);
    tag_t idx_tag[] = R16TAG(tid, index);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "16";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 2; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opq(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R64TAG(tid, base);
    tag_t idx_tag[] = R64TAG(tid, index);

    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "64";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 8; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(base_tag[2], idx_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(base_tag[3], idx_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(base_tag[4], idx_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(base_tag[5], idx_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(base_tag[6], idx_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(base_tag[7], idx_tag[7]);
}


static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opl(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R32TAG(tid, base);
    tag_t idx_tag[] = R32TAG(tid, index);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "32";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 4; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(base_tag[2], idx_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(base_tag[3], idx_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_u(THREADID tid, uint32_t src)
{
    tag_t tmp_tag = RTAG(tid)[src][1];

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(RTAG(tid)[DFT_REG_RAX][0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(RTAG(tid)[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_l(THREADID tid, uint32_t src)
{
    tag_t tmp_tag = RTAG(tid)[src][0];

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(RTAG(tid)[DFT_REG_RAX][0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(RTAG(tid)[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw(THREADID tid, uint32_t src)
{
    tag_t tmp_tag[] = {RTAG(tid)[src][0], RTAG(tid)[src][1]};
    tag_t dst1_tag[] = {RTAG(tid)[DFT_REG_RDX][0], RTAG(tid)[DFT_REG_RDX][1]};
    tag_t dst2_tag[] = {RTAG(tid)[DFT_REG_RAX][0], RTAG(tid)[DFT_REG_RAX][1]};

    RTAG(tid)[DFT_REG_RDX][0] = tag_combine(dst1_tag[0], tmp_tag[0]);
    RTAG(tid)[DFT_REG_RDX][1] = tag_combine(dst1_tag[1], tmp_tag[1]);
    
    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(dst2_tag[0], tmp_tag[0]);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(dst2_tag[1], tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opq(THREADID tid, uint32_t src)
{ 
    tag_t tmp_tag[] = R64TAG(tid, src);
    tag_t dst1_tag[] = R64TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}


static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl(THREADID tid, uint32_t src)
{ 
    tag_t tmp_tag[] = R32TAG(tid, src);
    tag_t dst1_tag[] = R32TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opb(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag = MTAG(src);
    tag_t dst_tag[] = R16TAG(tid, DFT_REG_RAX);

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(dst_tag[0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(dst_tag[1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M16TAG(src);
    tag_t dst1_tag[] = R16TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R16TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 2; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opq(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M64TAG(src);
    tag_t dst1_tag[] = R64TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}


static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M32TAG(src);
    tag_t dst1_tag[] = R32TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = R16TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opx(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);
    tag_t dst_tag[] = R128TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(dst_tag[4], src_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(dst_tag[5], src_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(dst_tag[6], src_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(dst_tag[7], src_tag[7]);
    RTAG(tid)[dst][8] = tag_combine(dst_tag[8], src_tag[8]);
    RTAG(tid)[dst][9] = tag_combine(dst_tag[9], src_tag[9]);
    RTAG(tid)[dst][10] = tag_combine(dst_tag[10], src_tag[10]);
    RTAG(tid)[dst][11] = tag_combine(dst_tag[11], src_tag[11]);
    RTAG(tid)[dst][12] = tag_combine(dst_tag[12], src_tag[12]);
    RTAG(tid)[dst][13] = tag_combine(dst_tag[13], src_tag[13]);
    RTAG(tid)[dst][14] = tag_combine(dst_tag[14], src_tag[14]);
    RTAG(tid)[dst][15] = tag_combine(dst_tag[15], src_tag[15]);

}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opq(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = R64TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(dst_tag[4], src_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(dst_tag[5], src_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(dst_tag[6], src_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(dst_tag[7], src_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opl(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = R32TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);
    tag_t dst_tag[] = R16TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opx(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M128TAG(src);
    tag_t dst_tag[] = R128TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(src_tag[4], dst_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(src_tag[5], dst_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(src_tag[6], dst_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(src_tag[7], dst_tag[7]);
    RTAG(tid)[dst][8] = tag_combine(src_tag[8], dst_tag[8]);
    RTAG(tid)[dst][9] = tag_combine(src_tag[9], dst_tag[9]);
    RTAG(tid)[dst][10] = tag_combine(src_tag[10], dst_tag[10]);
    RTAG(tid)[dst][11] = tag_combine(src_tag[11], dst_tag[11]);
    RTAG(tid)[dst][12] = tag_combine(src_tag[12], dst_tag[12]);
    RTAG(tid)[dst][13] = tag_combine(src_tag[13], dst_tag[13]);
    RTAG(tid)[dst][14] = tag_combine(src_tag[14], dst_tag[14]);
    RTAG(tid)[dst][15] = tag_combine(src_tag[15], dst_tag[15]);


}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);
    tag_t dst_tag[] = R64TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(src_tag[4], dst_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(src_tag[5], dst_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(src_tag[6], dst_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(src_tag[7], dst_tag[7]);

}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);
    tag_t dst_tag[] = R32TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_u(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = MTAG(dst);

    tag_t res_tag = tag_combine(dst_tag, src_tag);
    tag_dir_setb(tag_dir, dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_l(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = MTAG(dst);

    tag_t res_tag = tag_combine(dst_tag, src_tag);
    tag_dir_setb(tag_dir, dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = M16TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1])};
    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opq(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = M64TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1]), 
        tag_combine(dst_tag[2], src_tag[2]), tag_combine(dst_tag[3], src_tag[3]), tag_combine(dst_tag[4], src_tag[4]), tag_combine(dst_tag[5], src_tag[5]), tag_combine(dst_tag[6], src_tag[6]), tag_combine(dst_tag[7], src_tag[7])};

    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
    tag_dir_setb(tag_dir, dst+2, res_tag[2]);
    tag_dir_setb(tag_dir, dst+3, res_tag[3]);
    tag_dir_setb(tag_dir, dst+4, res_tag[4]);
    tag_dir_setb(tag_dir, dst+5, res_tag[5]);
    tag_dir_setb(tag_dir, dst+6, res_tag[6]);
    tag_dir_setb(tag_dir, dst+7, res_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = M32TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1]), 
        tag_combine(dst_tag[2], src_tag[2]), tag_combine(dst_tag[3], src_tag[3])};

    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
    tag_dir_setb(tag_dir, dst+2, res_tag[2]);
    tag_dir_setb(tag_dir, dst+3, res_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl4(THREADID tid)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RCX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RBX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl2(THREADID tid)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrx(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 16; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}


static void PIN_FAST_ANALYSIS_CALL
r_clrq(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 4; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrw(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 2; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrb_u(THREADID tid, uint32_t reg)
{
    threads_ctx[tid].vcpu.gpr_file[reg][1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL
r_clrb_l(THREADID tid, uint32_t reg)
{
    threads_ctx[tid].vcpu.gpr_file[reg][0] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][0];

     RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][1];

     RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][1];

     RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][0];

     RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opw(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);
  
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "16";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 2; i++){
        if(tag_count(src_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }
 

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opw(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);
   

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opq(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];

}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opx(THREADID tid, uint32_t dst, uint32_t src)
{

     
     tag_t src_tag[] = R128TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
     RTAG(tid)[dst][8] = src_tag[8];
     RTAG(tid)[dst][9] = src_tag[9];
     RTAG(tid)[dst][10] = src_tag[10];
     RTAG(tid)[dst][11] = src_tag[11];
     RTAG(tid)[dst][12] = src_tag[12];
     RTAG(tid)[dst][13] = src_tag[13];
     RTAG(tid)[dst][14] = src_tag[14];
     RTAG(tid)[dst][15] = src_tag[15];

}


static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opq(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "64";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 8; i++){
        if(tag_count(src_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
}


static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opl(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "32";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 4; i++){
        if(tag_count(src_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opq(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
}


static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opl(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);

    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opq_h(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[dst][i+8] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opx(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M128TAG(src);

    for (size_t i = 0; i < 16; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);

    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opbn(THREADID tid, ADDRINT dst, ADDRINT count, 
        ADDRINT eflags)
{
    tag_t src_tag = RTAG(tid)[DFT_REG_RAX][0];
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < count; i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < count; i++)
        {
            size_t dst_addr = dst - count + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag);

        }
	}
}
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_u(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_l(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opwn(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R16TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 1); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%2]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 1); i++)
        {
            size_t dst_addr = dst - (count << 1) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%2]);

        }
	}
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);

    tag_dir_setb(tag_dir, dst, src_tag[0]);
    tag_dir_setb(tag_dir, dst+1, src_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opqn(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R64TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%8]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            size_t dst_addr = dst - (count << 2) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%8]);

        }
	}
}


static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opln(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R32TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%4]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            size_t dst_addr = dst - (count << 2) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%4]);

        }
	}
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opq_h(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i+8]);
}


static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opq(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opx(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);

    for (size_t i = 0; i < 16; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);

    for (size_t i = 0; i < 4; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opw(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);

    for (size_t i = 0; i < 2; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opb(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opq(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}


static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opl(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);

    for (size_t i = 0; i < 4; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
rep_predicate(BOOL first_iteration)
{
	/* return the flag; typically this is true only once */
	return first_iteration; 
}

static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opw(THREADID tid, ADDRINT src)
{
    for (size_t i = 0; i < 8; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 1):((i-1) << 1);
        tag_t src_tag[] = M16TAG(src + offset);
        RTAG(tid)[DFT_REG_RDI+i][0] = src_tag[0];
        RTAG(tid)[DFT_REG_RDI+i][1] = src_tag[1];


    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opl(THREADID tid, ADDRINT src)
{
    for (size_t i = 0; i < 8; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 2):((i-1) << 2);
        tag_t src_tag[] = M32TAG(src + offset);
        RTAG(tid)[DFT_REG_RDI+i][0] = src_tag[0];
        RTAG(tid)[DFT_REG_RDI+i][1] = src_tag[1];
        RTAG(tid)[DFT_REG_RDI+i][2] = src_tag[2];
        RTAG(tid)[DFT_REG_RDI+i][3] = src_tag[3];

    }
}

static void PIN_FAST_ANALYSIS_CALL
r2m_save_opw(THREADID tid, ADDRINT dst)
{
    for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 1):((i-1) << 1);
        tag_t src_tag[] = R16TAG(tid, i);

        tag_dir_setb(tag_dir, dst + offset, src_tag[0]);
        tag_dir_setb(tag_dir, dst + offset + 1, src_tag[1]);



    }
}

static void PIN_FAST_ANALYSIS_CALL
r2m_save_opl(THREADID tid, ADDRINT dst)
{
    for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 2):((i-1) << 2);
        tag_t src_tag[] = R32TAG(tid, i);

        for (size_t j = 0; j < 4; j++)
            tag_dir_setb(tag_dir, dst + offset + j, src_tag[j]);


    }
}

static void PIN_FAST_ANALYSIS_CALL
file_r2r_lea(THREADID tid, uint32_t reg_dest, uint32_t reg_src, uint32_t size_dest, uint32_t size_src){
        std::vector<tag_t> src_tag(size_src);
        get_array_reg(tid, reg_src, size_src, src_tag);

        for(size_t i=0;i<min(size_src,size_dest);i++){
                RTAG(tid)[reg_dest][i] = src_tag[i];
        }
        for(size_t i= min(size_src,size_dest);i<size_dest;i++){
                RTAG(tid)[reg_dest][i] = tag_traits<tag_t>::cleared_val;
        }
        src_tag.clear();
}

static void PIN_FAST_ANALYSIS_CALL
file_m2r_movzx(THREADID tid, uint32_t reg_dest, ADDRINT src_addr, uint32_t size_dest, uint32_t size_src){
        std::vector<tag_t> src_tag(size_src);
        if(file_tag_testb(src_addr)){
                get_array_mem(src_addr, size_src, src_tag);
                //      LOG(tag_sprint(src_tag[0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");

                for(size_t i=0;i<min(size_src,size_dest);i++){
                        RTAG(tid)[reg_dest][i] = src_tag[i];
                }
                for(size_t i= min(size_src,size_dest);i<size_dest;i++){
                        RTAG(tid)[reg_dest][i] = tag_traits<tag_t>::cleared_val;
                }
        }
        //LOG(tag_sprint(RTAG(tid)[reg_dest][0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");
}

static void PIN_FAST_ANALYSIS_CALL
file_shrm(ADDRINT addr, uint32_t size_dest, uint32_t no_bits){
        std::vector<tag_t> dest_tag(size_dest);
        get_array_mem(addr, size_dest, dest_tag);
//      LOG("shrm " + to_string(no_bits) + "\n");
        //      LOG(tag_sprint(src_tag[0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");
        uint32_t to_transfer = no_bits/8;
        int limit = (int)(size_dest-to_transfer)<0?0:size_dest-to_transfer;
        for(int32_t i=0;i<limit;i++){
                tagmap_setb_with_tag(addr+i, dest_tag[i+to_transfer]);
        }
        for(int i=(int)size_dest-1;i>=(int)limit;i--){
                tagmap_setb_with_tag(addr+i, tag_traits<tag_t>::cleared_val);
        }
}

static void PIN_FAST_ANALYSIS_CALL
file_shlr(THREADID tid, uint32_t reg_dest, uint32_t size_dest, uint32_t no_bits){
        std::vector<tag_t> dest_tag(size_dest);
        get_array_reg(tid, reg_dest, size_dest, dest_tag);
//      LOG("shlr " + to_string(no_bits) + "\n");
        uint32_t to_transfer = no_bits/8;
        for(uint32_t i=to_transfer;i<size_dest;i++){
                RTAG(tid)[reg_dest][i] = dest_tag[i-to_transfer];
        }
        for(size_t i=0;i<to_transfer;i++){
                RTAG(tid)[reg_dest][i] = tag_traits<tag_t>::cleared_val;
        }
        //LOG(tag_sprint(RTAG(tid)[reg_dest][0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");
}

static void PIN_FAST_ANALYSIS_CALL
file_shlm(ADDRINT addr, uint32_t size_dest, uint32_t no_bits){
        std::vector<tag_t> dest_tag(size_dest);
        get_array_mem(addr, size_dest, dest_tag);
//      LOG("shlm " + to_string(no_bits) + "\n");
        //      LOG(tag_sprint(src_tag[0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");
        uint32_t to_transfer = no_bits/8;
        for(uint32_t i=to_transfer;i<size_dest;i++){
                tagmap_setb_with_tag(addr+i, dest_tag[i-to_transfer]);
        }
        for(size_t i=0;i<=to_transfer;i++){
                tagmap_setb_with_tag(addr+i, tag_traits<tag_t>::cleared_val);
        }
}

static void PIN_FAST_ANALYSIS_CALL
file_shrr(THREADID tid, uint32_t reg_dest, uint32_t size_dest, uint32_t no_bits){
        std::vector<tag_t> dest_tag(size_dest);
        get_array_reg(tid, reg_dest, size_dest, dest_tag);
//              LOG("shrr " + to_string(no_bits) + "\n");
//              LOG(tag_sprint(dest_tag[0]) + " " + decstr(size_dest) + " " + "\n");
        uint32_t to_transfer = no_bits/8;
        int limit = (int)(size_dest-to_transfer)<0?0:size_dest-to_transfer;
        for(int32_t i=0;i<limit;i++){
                RTAG(tid)[reg_dest][i] = dest_tag[i+to_transfer];
        }
//      LOG(to_string(limit) + "\n");
        for(int i=(int)size_dest-1;i>=(int)limit;i--){
//              LOG(to_string(i) + "\n");
                RTAG(tid)[reg_dest][i] = tag_traits<tag_t>::cleared_val;
        }
//      LOG(to_string(limit) + "\n");
        //LOG(tag_sprint(RTAG(tid)[reg_dest][0]) + " " + decstr(size_dest) + " " + decstr(size_src) + "\n");
}

static void PIN_FAST_ANALYSIS_CALL
file_bswap(THREADID tid,uint32_t reg_dest, uint32_t size){
        std::vector<tag_t> dest_tag(size);
        get_array_reg(tid, reg_dest, size, dest_tag);

        for(uint32_t i=0;i<size/2;i++){

                RTAG(tid)[reg_dest][size-(i+1)] = dest_tag[i];
                RTAG(tid)[reg_dest][i] = dest_tag[size-(i+1)];
        }
}



static void PIN_FAST_ANALYSIS_CALL
file_cmp_r2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, uint32_t reg_src, uint64_t reg_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	get_array_reg(tid, reg_src, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			output[2] = StringFromAddrint(ins_address);
			fl = 1;
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(reg_dest_val);
				output[20] = hexstr(reg_src_val);
				break;
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr((uint32_t)reg_src_val);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr((uint16_t)reg_src_val);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr((uint8_t)reg_src_val);
				break;
		}

		output[0] = std::to_string(size_dest*8);
		output[1] = "reg reg";
		print_log();
	}
}

static void PIN_FAST_ANALYSIS_CALL
file_cmp_m2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, ADDRINT src_addr, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	if(!file_tag_testb(src_addr)){
		return;
	}
	get_array_mem(src_addr, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			output[2] = StringFromAddrint(ins_address);
			fl = 1;
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(reg_dest_val);
				output[20] = hexstr(*(uint64_t *)src_addr);
				break;
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr(*(uint32_t *)src_addr);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr(*(uint16_t *)src_addr);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr(*(uint8_t *)src_addr);
				break;
		}
		output[0] = std::to_string(size_dest*8);
		output[1] = "reg mem";
		print_log();
	}
}

static void PIN_FAST_ANALYSIS_CALL
file_cmp_i2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, uint32_t imm_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	//LOG(StringFromAddrint(ins_address) + "\n");
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr((uint32_t)imm_src_val);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr((uint16_t)imm_src_val);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr((uint8_t)imm_src_val);
				break;
		}	
		output[0] = std::to_string(size_dest*8);
		output[1] = "reg imm";
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_r2m(THREADID tid, ADDRINT ins_address, ADDRINT dest_addr, uint32_t reg_src, uint64_t reg_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	if(!file_tag_testb(dest_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	get_array_reg(tid, reg_src, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(*(uint64_t *)dest_addr);
				output[20] = hexstr(reg_src_val);
				break;
			case 4:
				output[19] = hexstr(*(uint32_t *)dest_addr);
				output[20] = hexstr((uint32_t)reg_src_val);
				break;
			case 2:
				output[19] = hexstr(*(uint16_t *)dest_addr);
				output[20] = hexstr((uint16_t)reg_src_val);
				break;
			case 1:
				output[19] = hexstr(*(uint8_t *)dest_addr);
				output[20] = hexstr((uint8_t)reg_src_val);
				break;
		}
		output[0] = std::to_string(size_dest*8);
		output[1] = "mem reg";
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_m2m(ADDRINT ins_address, ADDRINT dest_addr, ADDRINT src_addr, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	if(!file_tag_testb(dest_addr) ||!file_tag_testb(src_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	get_array_mem(src_addr, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(dest_tag[i].numberOfOnes() > 0 && dest_tag[i].numberOfOnes() <= (uint32_t)limit_offset){
			for(tag_t::const_iterator it = dest_tag[i].begin();it != dest_tag[i].end();it++){
	                                //file_offsets[make_pair(*it,1)] = 1;
			//file_offsets[*it] = 1;

			}
         //               LOG(tag_sprint(dest_tag[i]) + " CMPS" );
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(src_tag[i].numberOfOnes() > 0 && src_tag[i].numberOfOnes() <= (uint32_t)limit_offset){
			for(tag_t::const_iterator it = src_tag[i].begin();it != src_tag[i].end();it++){
                                //file_offsets[make_pair(*it,1)] = 1;

				//file_offsets[*it] = 1;
			}
           //             LOG(tag_sprint(src_tag[i]) + " CMPS" );
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
                switch(size_dest){
                        case 8:
                        case 4:
                                output[19] = hexstr(*(uint32_t *)dest_addr);
                                output[20] = hexstr(*(uint32_t *)src_addr);
                                break;
                        case 2:
                                output[19] = hexstr(*(uint16_t *)dest_addr);
                                output[20] = hexstr(*(uint16_t *)src_addr);
                                break;
                        case 1:
                                output[19] = hexstr(*(uint8_t *)dest_addr);
                                output[20] = hexstr(*(uint8_t *)src_addr);
                                break;
                }

		output[0] = std::to_string(size_dest*8);
		output[1] = "mem mem";
             //   LOG("\n");
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_i2m(ADDRINT ins_address, ADDRINT dest_addr, uint32_t imm_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);

	if(!file_tag_testb(dest_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
			case 4:
				output[19] = hexstr(*(uint32_t *)dest_addr);
				break;
			case 2:
				output[19] = hexstr(*(uint16_t *)dest_addr);
				break;
			case 1:
				output[19] = hexstr(*(uint8_t *)dest_addr);
				break;
		}
		output[20] = hexstr(imm_src_val);
		output[0] = std::to_string(size_dest*8);
		output[1] = "mem imm";
		print_log();
	}
}



















////////////////////////////// File Taint Ends ////////////////////////////////////


static BOOL TRACKING = FALSE;
static BOOL DEBUG_LIB = FALSE;

static ADDRINT get_rsp(THREADID tid)
{
	list_head_t *iter;
	rt_ctx_t* pFunc;

	iter = threads_ctx[tid].rt_stack_head.next;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		pFunc = list_entry(iter, rt_ctx_t, rt_stack);
		if (pFunc->type == FUNC_CTX_TYPE){
			break;
		}
		iter = iter->next;
	}

	if (iter == &(threads_ctx[tid].rt_stack_head))
		return threads_ctx[tid].highest_rsp;
	return pFunc->rsp;
}

static BOOL sanity_check_rtx(THREADID tid){
	rt_ctx_t* pFunc;
	list_head_t *iter;

	iter = threads_ctx[tid].rt_stack_head.next;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		pFunc = list_entry(iter, rt_ctx_t, rt_stack);
		if (pFunc->rsp < 100){
			return FALSE;
		}
		iter = iter->next;
	}
	return TRUE;
}

	
static inline void 
r_clr(THREADID tid, UINT32 reg_indx)
{
	memset(&(threads_ctx[tid].vcpu.gpr[reg_indx]),0,sizeof(TAG_TYPE));
}

static void PIN_FAST_ANALYSIS_CALL
r_clr_fast(THREADID tid, UINT32 reg_indx)
{
	r_clr(tid, reg_indx);
}

static inline void 
m_clrn(ADDRINT addr, UINT32 len)
{
	TAG_TYPE* ptag;

	for (UINT64 i=addr;i<addr+len;i++){
		if (tagmap_testb(i)){
			ptag = tagmap_get_ref(i);
			if (ptag == NULL)
				return;
			ptag->isPointer = FALSE;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL
m_clrn_fast(ADDRINT addr, UINT32 len)
{
	m_clrn(addr, len);
}

static inline void add_to_loop(ADDRINT addr, rt_ctx_t *loop_ctx)
{
	loop_ctx->dmaps->at(loop_ctx->iterations - 1)->insert(addr);
}

rt_ctx_t* func_lookup(THREADID tid, ADDRINT addr)
{
	rt_ctx_t* pFunc;
	list_head_t *iter;
	
	iter = threads_ctx[tid].rt_stack_head.next;
	if ((addr < threads_ctx[tid].lowest_rsp)||(addr > threads_ctx[tid].highest_rsp))
		return NULL;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		pFunc = list_entry(iter, rt_ctx_t, rt_stack);
		if ((pFunc->type == FUNC_CTX_TYPE)&&(addr < pFunc->rsp))
			return pFunc;
		iter = iter->next;
	}
	return NULL;
}

static void
select_base(THREADID tid, ADDRINT addr, ADDRINT new_base, UINT32 size, BOOL checkloop)
{
	TAG_TYPE *ptag;
	rt_ctx_t* ctx;
	ADDRINT old_base;
	BOOL inLoop = false;
	
	ptag = tagmap_get_ref(addr);
	if (ptag == NULL)
		return;
	if (new_base == 0)
		goto SELECT_FINISH;
	if (ptag->size == 0)
		ptag->size = size;
	//if in loop, sync when loop finished
	if (checkloop && !list_empty(&threads_ctx[tid].rt_stack_head)){
		ctx = list_entry(threads_ctx[tid].rt_stack_head.next, rt_ctx_t, rt_stack);
		if (ctx->type == LOOP_CTX_TYPE){
			ptag->loop_base = new_base;
			ptag->loop_access_size = (size!=0)?size:ptag->loop_access_size;
			add_to_loop(addr,ctx);
			inLoop = true;
		}
	}

	if ((ptag->base_addr == new_base)||(new_base == addr)){
		if ((size == 0) && !TEST_MASK(ptag->dflag, ARRAY_ELEMENT_MASK))
			goto SELECT_FINISH;
	
		if(inLoop){	
			ptag->size = (size < ptag->size)?size:ptag->size;
		}
		else{
			ptag->size = (size > ptag->size)?size:ptag->size;
		}
		ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		goto SELECT_FINISH;
	}

	if (ptag->base_addr == addr){
		ptag->base_addr = new_base;
		ptag->size = (size!=0)?size:ptag->size;
		if (not inLoop)
			ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		else
			ptag->dflag = SET_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		goto SELECT_FINISH;
	}

	if (ptag->base_addr == 0){
		ptag->base_addr = new_base;
		ptag->size = size;
		if (not inLoop)
			ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		else
			ptag->dflag = SET_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		goto SELECT_FINISH;
	}
	old_base = ptag->base_addr;
	
	if (TEST_MASK(ptag->dflag, ARRAY_ELEMENT_MASK)&&(not inLoop)){
		ptag->base_addr = new_base;
		ptag->size = (size!=0)?size:ptag->size;
		ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		goto SELECT_FINISH;
	}
	
	//choose the closer one
	if (llabs(old_base-addr) > llabs(new_base-addr) && new_base<addr){
		ptag->base_addr = new_base;
		ptag->size = (size!=0)?size:ptag->size;
		if (not inLoop)
			ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		else
			ptag->dflag = SET_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		goto SELECT_FINISH;
	}
	
	//base should below the address
	if (old_base > addr){
		if (old_base > new_base){
			ptag->base_addr = new_base;
			ptag->size = (size!=0)?size:ptag->size;
			if (not inLoop)
				ptag->dflag = CLR_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
			else
				ptag->dflag = SET_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
		}
		goto SELECT_FINISH;
	}
	else if (new_base > addr){
		goto SELECT_FINISH;
	}
SELECT_FINISH:
 
	return;
}


static void dfs_insert(ADDRINT addr, UINT64 loops_iter, rt_ctx_t* ploop, ARRAY_SET_T *parray)
{
	if (loops_iter == 0)
		return;

	TAG_TYPE *ptag;
	ARRAY_SET_T::iterator iter;

	ptag = tagmap_get_ref(addr);
	if (ptag == NULL)
		return;

	iter = ploop->dmaps->at(loops_iter)->find(ptag->loop_base);
	if (iter!=ploop->dmaps->at(loops_iter)->end()){
		//Found
		parray->insert(ptag->loop_base);
		addr = ptag->loop_base;
	}
	dfs_insert(addr, loops_iter-1, ploop, parray);
	return;
}

static void sync_loop(THREADID tid, rt_ctx_t* ploop)
{
	UINT64 i;
	ARRAY_SET_T *praw, *paccessed, *parray, container;
	ARRAY_SET_T::iterator set_iter, next_iter;
	ARRAY_MAP_T arr_maps;
	ARRAY_MAP_T::iterator map_iter;
	ADDRINT addr;
	TAG_TYPE *ptag;
	BOOL found;
	heap_ctx_t* heap_ctx;
	rt_ctx_t* func_ctx;

	if (ploop->iterations == 1){
		for (i=0;i<ploop->iterations;i++){
			praw = ploop->dmaps->at(i);
			for (set_iter = praw->begin(); set_iter!=praw->end(); set_iter++){
				addr = *set_iter;
				ptag = tagmap_get_ref(addr);
				if (ptag == NULL)
					return;
				ptag->loop_base = 0;
				ptag->loop_access_size = 0;
			}
		}
	}
	else{
		paccessed = new ARRAY_SET_T ();
		for (int j=ploop->iterations-1; j>=0; j--){
			praw = ploop->dmaps->at(j);
			std::set_difference(praw->begin(), praw->end(), 
					paccessed->begin(), paccessed->end(),
					std::inserter(container, container.begin()));
			*praw = ARRAY_SET_T ();
			*praw = container;
			container = ARRAY_SET_T ();
			paccessed->insert(praw->begin(), praw->end());
		}

		//clean the repeat items
		*paccessed = ARRAY_SET_T ();
		for (int j=ploop->iterations-1; j>=0; j--){
			praw = ploop->dmaps->at(j);
			for (set_iter = praw->begin(); set_iter!=praw->end(); set_iter++){
				parray = new ARRAY_SET_T ();
				dfs_insert(*set_iter, j, ploop, parray);
				if (parray->empty()){
					paccessed->insert(*set_iter);
					delete parray;
				}
				else{
					parray->insert(*set_iter);
					addr = *(parray->begin()); //use the smallest addr as key
					if (arr_maps.find(addr) == arr_maps.end()){
						arr_maps[addr] = parray;
					}
					std::set_union(arr_maps[addr]->begin(), arr_maps[addr]->end(), 
							parray->begin(), parray->end(),
							std::inserter(container, container.begin()));
					*(arr_maps[addr]) = ARRAY_SET_T ();
					*(arr_maps[addr]) = container;
					container = ARRAY_SET_T ();
				}
			}
		}
		//handle the access array
		for (set_iter = paccessed->begin(); set_iter!=paccessed->end(); set_iter++){
			addr = *set_iter;
			ptag = tagmap_get_ref(addr);
			if (ptag == NULL)
				return;
			if (ptag->loop_base == 0)
				continue;
			found = FALSE;
			for (map_iter = arr_maps.begin(); map_iter!=arr_maps.end(); map_iter++){
				praw = map_iter->second;
				if (praw->find(addr)!=praw->end()){
					found = TRUE;
					break;
				}
				if (map_iter->first == ptag->loop_base){
					found = TRUE;
					praw->insert(addr);
					break;
				}
			}
			if (!found){
				arr_maps[ptag->loop_base] = new ARRAY_SET_T ();
				arr_maps[ptag->loop_base]->insert(addr);
			}
		}
		delete paccessed;

		//For each array, dump them to file. 
		for (map_iter = arr_maps.begin(); map_iter!=arr_maps.end(); map_iter++){
			praw = map_iter->second;
			assert(praw->size() > 0);

			addr = *(praw->begin());
			ptag = tagmap_get_ref(addr);
			if (ptag == NULL)
				return;
			if (praw->size() == 1){
				//Only one element, then it is no array
				select_base(tid, addr, ptag->loop_base, ptag->loop_access_size, FALSE);
				if ((ptag->loop_base == ptag->base_addr)&&(ptag->loop_access_size == ptag->size))
					ptag->dflag = SET_MASK(ptag->dflag, ARRAY_ELEMENT_MASK);
				ptag->loop_base = 0;
				ptag->loop_access_size = 0;
				delete praw;
				continue;
			}
			PIN_MutexLock(&HeapLock);
			heap_ctx = heap_lookup(addr);
			if (heap_ctx!=NULL){
				write_heap_array(heap_ctx->pdesc, heap_ctx->start,praw);
			}
			else{
				func_ctx = func_lookup(tid, addr);
				if (func_ctx != NULL){
					write_stack_array(func_ctx->addr, func_ctx->rsp, praw);
				}
			}
			PIN_MutexUnlock(&HeapLock);
			delete praw;
		}
	}
	//clean up
	for (i=0;i<ploop->iterations;i++)
		delete ploop->dmaps->at(i);
	delete ploop->dmaps;
}


static inline void
push_mem(THREADID tid, ADDRINT src_addr, ADDRINT dst_addr)
{
	TAG_TYPE *srctag, *dsttag, *ptag_org;
	UINT64 mContent;
	EXCEPTION_INFO einfo;

	srctag = tagmap_get_ref(src_addr+7);
	if (srctag == NULL)
		return;
	if (srctag->isPointer){
		dsttag = tagmap_get_ref(dst_addr+7);
		if (dsttag == NULL)
			return;
		dsttag->isPointer = TRUE;
		if (PIN_SafeCopyEx(&mContent,(void*)src_addr, sizeof(UINT64), &einfo) != sizeof(UINT64)){
			srctag->isPointer = FALSE;
			dsttag->isPointer = FALSE;
			return;
		}
		ptag_org = tagmap_get_ref(dst_addr);
		if (ptag_org == NULL)
			return;
		ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
		dsttag->temp_base = mContent;
	}
	else{
		m_clrn(dst_addr,15);
	}
}

static void PIN_FAST_ANALYSIS_CALL
push_mem_fast(THREADID tid, ADDRINT src_addr, ADDRINT dst_addr)
{
	push_mem(tid, src_addr, dst_addr);
}

static inline void
pop_mem(THREADID tid, ADDRINT src_addr, ADDRINT dst_addr)
{
	TAG_TYPE *srctag, *dsttag, *ptag_org;
	UINT64 mContent;
	EXCEPTION_INFO einfo;

	srctag = tagmap_get_ref(src_addr+7);
	if (srctag == NULL)
		return;
	if (srctag->isPointer){
		dsttag = tagmap_get_ref(dst_addr+7);
		if (dsttag == NULL)
			return;
		dsttag->isPointer = TRUE;
		if (PIN_SafeCopyEx(&mContent,(void*)src_addr, sizeof(UINT64), &einfo) != sizeof(UINT64)){
			srctag->isPointer = FALSE;
			dsttag->isPointer = FALSE;
			return;
		}
		ptag_org = tagmap_get_ref(dst_addr);
		if (ptag_org == NULL)
			return;
		ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
		select_base(tid, mContent, srctag->temp_base, 0, TRUE);
	}
	else{
		m_clrn(dst_addr,15);
	}
}

static void PIN_FAST_ANALYSIS_CALL
pop_mem_fast(THREADID tid, ADDRINT src_addr, ADDRINT dst_addr)
{
	pop_mem(tid, src_addr,dst_addr);
}

static inline void
push_reg(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	TAG_TYPE *srctag, *dsttag, *ptag_org;
	srctag = &(threads_ctx[tid].vcpu.gpr[reg_indx]);
	if (srctag->isPointer){
		dsttag = tagmap_get_ref(addr+7);
		if (dsttag == NULL)
			return;
		dsttag->isPointer = TRUE;
		ptag_org = tagmap_get_ref(addr);
		if (ptag_org == NULL)
			return;
		ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
		dsttag->temp_base = srctag->base_addr;
	}
	else{
		m_clrn(addr,15);
	}
}

static void PIN_FAST_ANALYSIS_CALL
push_reg_fast(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	push_reg(tid, reg_indx, addr);
}

static inline void
pop_reg(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	TAG_TYPE *srctag, *dsttag, *ptag_org;
	srctag = tagmap_get_ref(addr+7);
	if (srctag == NULL)
		return;
	dsttag = &(threads_ctx[tid].vcpu.gpr[reg_indx]);
	if (srctag->isPointer){
		dsttag->isPointer = TRUE;
		ptag_org = tagmap_get_ref(addr);
		if (ptag_org == NULL)
			return;
		ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
		dsttag->base_addr = srctag->temp_base;
	}
	else{
		r_clr(tid, reg_indx);
	}
}

static void PIN_FAST_ANALYSIS_CALL
pop_reg_fast(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	pop_reg(tid, reg_indx, addr);
}

static inline void 
r2m_set(THREADID tid, UINT32 reg_indx, ADDRINT addr, const CONTEXT* ctxt, UINT32 size)
{
	TAG_TYPE* ptag, *ptag_org;
	UINT64 mContent;
	EXCEPTION_INFO einfo;

	if (DEBUG_IP == 0x7ffff7ffa98a)
		printf("Inside r2mset\n");

	if (!threads_ctx[tid].vcpu.gpr[reg_indx].isPointer){
		m_clrn(addr,8);
		return;
	}

	ptag = tagmap_get_ref(addr+7);
	if (ptag == NULL)
		return;
	ptag->isPointer = TRUE;
	ptag_org = tagmap_get_ref(addr);
	if (ptag_org == NULL)
		return;
	ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
	m_clrn(addr,7);
	if (!ctxt){
		//Indicate the memory content is setting up, so it is a post instrument
		if (PIN_SafeCopyEx(&mContent,(void*)addr, sizeof(UINT64), &einfo) != sizeof(UINT64)){
			ptag->isPointer = FALSE;
			return;
		}
	}
	else{
		mContent = PIN_GetContextReg(ctxt, VCPU_INDX(reg_indx));
	}
	ptag = tagmap_get_ref(mContent);
	if (ptag == NULL){
		threads_ctx[tid].vcpu.gpr[reg_indx].isPointer = FALSE;
		m_clrn(addr,8);
		return;
	}
	select_base(tid, mContent, threads_ctx[tid].vcpu.gpr[reg_indx].base_addr, size, TRUE);
	threads_ctx[tid].vcpu.gpr[reg_indx].dflag = SET_MASK(threads_ctx[tid].vcpu.gpr[reg_indx].dflag, ACCESS_MASK);
	if (ctxt){
		threads_ctx[tid].vcpu.gpr[reg_indx].base_addr = mContent;
	}
}

static void PIN_FAST_ANALYSIS_CALL
r2m_set_fast(THREADID tid, UINT32 reg_indx, ADDRINT addr, const CONTEXT *ctxt)
{
	r2m_set(tid, reg_indx, addr, ctxt, 0);
}

static inline void
m2r_set(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	TAG_TYPE* ptag;
	UINT64 mContent;
	EXCEPTION_INFO einfo;
	
	if (tagmap_testb(addr+7)){
		ptag = tagmap_get_ref(addr+7);
		if (ptag == NULL)
			return;
		if (ptag->isPointer){
			if (PIN_SafeCopyEx(&mContent,(void*)addr, sizeof(UINT64), &einfo) != sizeof(UINT64)){
				ptag->isPointer = FALSE;
				threads_ctx[tid].vcpu.gpr[reg_indx].isPointer = FALSE;
				return;
			}
			threads_ctx[tid].vcpu.gpr[reg_indx].isPointer = TRUE;
			threads_ctx[tid].vcpu.gpr[reg_indx].dflag = SET_MASK(threads_ctx[tid].vcpu.gpr[reg_indx].dflag, POINTER_MASK);
			threads_ctx[tid].vcpu.gpr[reg_indx].base_addr = mContent;
			return;
		}
	}
	r_clr(tid, reg_indx);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_set_fast(THREADID tid, UINT32 reg_indx, ADDRINT addr)
{
	m2r_set(tid,reg_indx, addr);
}

static inline void 
r2r_set(THREADID tid, UINT32 src_indx, UINT32 dst_indx)
{
	threads_ctx[tid].vcpu.gpr[dst_indx] = threads_ctx[tid].vcpu.gpr[src_indx];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_set_fast(THREADID tid, UINT32 src_indx, UINT32 dst_indx)
{
	r2r_set(tid, src_indx, dst_indx);
}

static void 
m2m_set(THREADID tid, ADDRINT src_addr, UINT64 old_content, ADDRINT dst_addr, UINT32 size)
{
	TAG_TYPE* ptag_src, *ptag_dst, *ptag_org;
	UINT64 mContent;
	
	if (tagmap_testb(src_addr+7)){
		ptag_src = tagmap_get_ref(src_addr+7);
		if (ptag_src == NULL)
			return;
		if (ptag_src->isPointer){
			ptag_dst = tagmap_get_ref(dst_addr+7);
			if (ptag_dst == NULL)
				return;
			ptag_dst->isPointer = TRUE;
			ptag_org = tagmap_get_ref(dst_addr);
			if (ptag_org == NULL)
				return;
			ptag_org->dflag = SET_MASK(ptag_org->dflag, POINTER_MASK);
			m_clrn(dst_addr,7);
			PIN_SafeCopy(&(mContent),(void*)dst_addr,sizeof(UINT64));
			select_base(tid, mContent, old_content, size, TRUE);
			return;
		}
	}
	m_clrn(dst_addr,8);
}

static void PIN_FAST_ANALYSIS_CALL
reg_record(THREADID tid, const CONTEXT* ctxt, REG reg, UINT8 indx)
{
	if ((reg == REG_INVALID())||(REG_INDX(reg) == GRP_NUM)){
		threads_ctx[tid].opnd[indx].value = (reg == REG_INVALID()) ? 0 : PIN_GetContextReg(ctxt,reg);
		threads_ctx[tid].opnd[indx].type = TYPE_IMM;
		return;
	}
	threads_ctx[tid].opnd[indx].value = PIN_GetContextReg(ctxt,reg);
	threads_ctx[tid].opnd[indx].type = TYPE_REG;
	threads_ctx[tid].opnd[indx].reg = reg;
	threads_ctx[tid].opnd[indx].ptag = &(threads_ctx[tid].vcpu.gpr[REG_INDX(reg)]);
}

static void PIN_FAST_ANALYSIS_CALL
imm_record(THREADID tid, UINT32 imm, UINT8 indx)
{
	threads_ctx[tid].opnd[indx].value = imm;
	threads_ctx[tid].opnd[indx].type = TYPE_IMM;
}

static void PIN_FAST_ANALYSIS_CALL
mem_record(THREADID tid, ADDRINT addr, UINT8 indx)
{
	if (tagmap_get_ref(addr) == NULL){
		threads_ctx[tid].opnd[indx].type = TYPE_IMM;
		return;
	}
	PIN_SafeCopy(&(threads_ctx[tid].opnd[indx].value),(void*)addr,sizeof(UINT64));
	threads_ctx[tid].opnd[indx].type = TYPE_MEM;
	threads_ctx[tid].opnd[indx].addr = addr;
	threads_ctx[tid].opnd[indx].ptag = tagmap_get_ref(addr);
}

static void PIN_FAST_ANALYSIS_CALL
sync_opnd_after(THREADID tid, const CONTEXT* ctxt, UINT32 size)
{
	int i;
	opnd_t *pOpnd, *srcOpnd;
	UINT64 distance;
	EXCEPTION_INFO einfo;

	pOpnd = &(threads_ctx[tid].opnd[2]);
	if (pOpnd->type == TYPE_REG){
		pOpnd->value = PIN_GetContextReg(ctxt,pOpnd->reg);
	}
	else{
		PIN_SafeCopy(&(pOpnd->value),(void*)(pOpnd->addr),sizeof(UINT64));
		if (PIN_SafeCopyEx(&(pOpnd->value),(void*)(pOpnd->addr), sizeof(UINT64), &einfo) != sizeof(UINT64)){
			return;
		}
	};

	srcOpnd = NULL;
	distance = MAX_64BIT_VALUE;
	for (i=0; i<=OP_1; i++)
	{
		if (llabs(threads_ctx[tid].opnd[i].value - pOpnd->value) < (uint64_t)distance){
			distance = llabs(threads_ctx[tid].opnd[i].value - pOpnd->value);
			srcOpnd = &(threads_ctx[tid].opnd[i]);
		}
	};

	if (unlikely(distance > MAX_32BIT_VALUE)){
		if (pOpnd->type == TYPE_REG){
			r_clr(tid, REG_INDX(pOpnd->reg));
		}
		else if (pOpnd->type == TYPE_MEM){
			m_clrn(pOpnd->addr, 15);
		}
	}
	else{
		if ((pOpnd->type == TYPE_REG)&&(srcOpnd->type == TYPE_REG)){
			r2r_set(tid, REG_INDX(srcOpnd->reg), REG_INDX(pOpnd->reg));
		}
		else if ((pOpnd->type == TYPE_REG)&&(srcOpnd->type == TYPE_MEM)){
			m2r_set(tid, REG_INDX(pOpnd->reg), srcOpnd->addr);
		}
		else if ((pOpnd->type == TYPE_MEM)&&(srcOpnd->type == TYPE_REG)){
			r2m_set(tid, REG_INDX(srcOpnd->reg), pOpnd->addr, NULL, size);
		}
		else if ((pOpnd->type == TYPE_MEM)&&(srcOpnd->type == TYPE_MEM)){
			m2m_set(tid, srcOpnd->addr, srcOpnd->value,pOpnd->addr, size);
		}
		else if (pOpnd->type == TYPE_MEM){
			m_clrn(pOpnd->addr, 15);
		}
		else if (pOpnd->type ==TYPE_REG){
			r_clr(tid, REG_INDX(pOpnd->reg));
		}
	}
}

static void
deref_mem(THREADID tid, const CONTEXT* ctxt, 
		ADDRINT addr, REG base_reg, REG indx_reg, UINT32 len,
		BOOL isRead, REG rep_reg, BOOL hasRep, BOOL firstRep, ADDRINT ip, bool ismov)
{
	/*
	 * 1. addr got access flag, and its size is len
	 * 2. find the write base for the deref
	 */
	UINT64 rep_times;
	ADDRINT i;
	TAG_TYPE *ptag;
	if (DEBUG_IP == 0x7ffff7ffa98a)
		printf("Inside deref\n");

	ptag = tagmap_get_ref(addr);
	if (ptag == NULL)
		return;

	if (hasRep && (!firstRep))
		return;
	if(isRead && !ismov){
          tag_t t = file_tagmap_getb(addr);
	//  LOG(tag_sprint(t) + " " + StringFromAddrint(addr)  + "\n"); 
	  int sz = 0;
	  int prev = -1;
	  uint32_t mi = UINT_MAX;
	  for(size_t i=0;i<len;i++){
		ptag = tagmap_get_ref(addr+i);
        	if(ptag != NULL && tag_count(file_tagmap_getb(addr+i))){
                        tag_t t = file_tagmap_getb(addr+i);
                        int no = t.numberOfOnes();
			tag_t::const_iterator it = t.begin();
                        if(t.numberOfOnes() == 1){
                                if(prev == -1 || (*it+1 == (uint32_t)prev) || (*it-1 == (uint32_t)prev)){
                                        prev = *it;
                                        mi = std::min(mi,(uint32_t)prev);
					sz++;
                                }else{
                                        //fl = 0;
                                        break;
                                }
                        }else{
                                //fl = 0;
                                break;
                        }
			//LOG(tag_sprint(t) + " " + StringFromAddrint(addr) + " " +decstr(ptag->istaint) + "\n"); 
                        if(no <= limit_offset && no > 0){
                                if(ptag->istaint >= 1){
                                        std::string s = ptag->file_taint->gettaint();
					//LOG("istaint > 1 " + s + "\n");
                                        std::map<std::string, bool> m = ptag->file_taint->m;
                                        if(m.find(tag_sprint(t)) == m.end()){
                                                s += ":" + tag_sprint(t);
                                                Taint<std::string>* tstore = new Taint<std::string>(s);
                                                tstore->m = m;
                                                ptag->file_taint = tstore;
                                                ptag->istaint++; 
                                                ptag->file_taint->m[tag_sprint(t)] = 1;
                                        }
                                }else{
                                        Taint<std::string>* tstore = new Taint<std::string>(tag_sprint(t));
                                        ptag->file_taint = tstore;
                                        ptag->istaint = 1; 
                                        ptag->file_taint->m[tag_sprint(t)] = 1;
                                }
                        }else{  
                                if(ptag->istaint == 0){
                                        Taint<std::string>* tstore = new Taint<std::string>(std::string("{}"));
                                        ptag->file_taint = tstore;
                                        ptag->istaint = 0; 
                                }
                        }
                        std::string s = ptag->file_taint->gettaint();
			//LOG(s + " " + StringFromAddrint(addr) + "\n"); 
		}else{
                	 Taint<std::string>* tstore = new Taint<std::string>(std::string("{}"));
	                 ptag->file_taint = tstore;
        	         ptag->istaint = 0; 
		}
	   }
    	   if(sz != 0){
		if(file_offsets.find(std::make_pair(mi,sz)) == file_offsets.end()){
			file_offsets[std::make_pair(mi,sz)] = 1;
		}else{
			file_offsets[std::make_pair(mi,sz)]++;
		}
	   }
	}
	ptag = tagmap_get_ref(addr);

	//assert must has pointer mask
	if ((TRACKING)&&(addr >= threads_ctx[tid].lowest_rsp)&&(addr <= threads_ctx[tid].highest_rsp)){
		BOOL isPointerBase = FALSE, isPointerIndx = FALSE;
		if (!(base_reg == REG_INVALID()))
			isPointerBase = threads_ctx[tid].vcpu.gpr[REG_INDX(base_reg)].isPointer;
		if (!(indx_reg == REG_INVALID()))
			isPointerIndx = threads_ctx[tid].vcpu.gpr[REG_INDX(indx_reg)].isPointer;
		if (!((isPointerBase||isPointerIndx)&&(isPointerBase ^ isPointerIndx))){
			isPointerBase = FALSE;
			isPointerIndx = FALSE;
		}
		//assert((isPointerBase||isPointerIndx)&&(isPointerBase ^ isPointerIndx));
	}
	rep_times = 1;
	if (hasRep&&(!(rep_reg == REG_INVALID()))){
		rep_times = PIN_GetContextReg(ctxt, rep_reg);
		if (rep_times > 0x1000000){
			rep_times = 1;
		}
	}
	for (i=addr;i<(addr+len*rep_times);i+=len){
		ptag = tagmap_get_ref(i);
		ptag->dflag = SET_MASK(ptag->dflag,ACCESS_MASK);
		if (rep_times>1){
			ptag->dflag = SET_MASK(ptag->dflag,ARRAY_ELEMENT_MASK);
		};
		if (i!=addr){
			select_base(tid, i, i-len, len, FALSE);
		};
		if ((!TEST_MASK(ptag->dflag, READ_MASK)) && (!TEST_MASK(ptag->dflag, WRITE_MASK)))
		{
			if (isRead)
				ptag->dflag = SET_MASK(ptag->dflag, READ_MASK);
			else
				ptag->dflag = SET_MASK(ptag->dflag, WRITE_MASK);
		}
	}
	reg_record(tid, ctxt, base_reg, 0);
	reg_record(tid, ctxt, indx_reg, 1);
	threads_ctx[tid].fake_memop = addr;
	mem_record(tid, ADDRINT(&(threads_ctx[tid].fake_memop)), 2);
	sync_opnd_after(tid, ctxt, len);
}

static void load_taint(ADDRINT root, TAG_TYPE* ctag)
{
	if ((ctag->dlength <= 0)||(ctag->dtags==NULL))
		return;
	TAG_TYPE *ptag_src, *ptag_dst;
	ADDRINT addr;

	ptag_src = (TAG_TYPE*)ctag->dtags;

	for (addr = root - ctag->dlength;addr <= root; addr++)
	{
		ptag_dst = tagmap_get_ref(addr);
		ptag_dst->dflag = ptag_src[root - addr].dflag;
		ptag_dst->size = ptag_src[root - addr].size;
		ptag_dst->base_addr = root - ptag_src[root - addr].base_addr;
	}
}

static void store_taint(THREADID tid, rt_ctx_t* pfunc)
{
	TAG_TYPE *ctag;
	TAG_TYPE *ptag_src, *ptag_dst;

	int64_t diff =(int64_t) pfunc->rsp - (int64_t)threads_ctx[tid].lowest_rsp + 1;	
	ctag = tagmap_get_ref(pfunc->addr);
	if (diff > (int64_t)ctag->dlength){
		ctag->dtags = realloc(ctag->dtags, (pfunc->rsp - threads_ctx[tid].lowest_rsp + 1)*TAG_SIZE);
		assert(ctag->dtags != NULL);
		ptag_dst = (TAG_TYPE*)ctag->dtags;
		memset(&(ptag_dst[ctag->dlength]),0,(pfunc->rsp - threads_ctx[tid].lowest_rsp - ctag->dlength + 1)*TAG_SIZE);
		ctag->dlength = pfunc->rsp - threads_ctx[tid].lowest_rsp;
	}
	ptag_dst = (TAG_TYPE*)ctag->dtags;
	bool fl = 0;
	for (ADDRINT addr=threads_ctx[tid].lowest_rsp; addr <= pfunc->rsp; addr++){
		ptag_src = tagmap_get_ref(addr);
		if(file_tag_testb(addr)){
			tag_t t = file_tagmap_getb(addr);
			int no = t.numberOfOnes();
			if(ptag_src[0].istaint >= 1){
				ptag_dst[pfunc->rsp - addr].file_taint = ptag_src[0].file_taint;
				ptag_dst[pfunc->rsp - addr].istaint = ptag_src[0].istaint;
                                std::string s = ptag_src[0].file_taint->gettaint();
                                std::map<std::string, bool> m = ptag_src[0].file_taint->m;
                                if(no <= limit_offset && no > 0 && m.find(tag_sprint(t)) == m.end()){
                                       s += ":" + tag_sprint(t);
                                       Taint<std::string>* tstore = new Taint<std::string>(s);
                                       tstore->m = m;
                                       ptag_dst[pfunc->rsp - addr].file_taint = tstore;
                                       ptag_dst[pfunc->rsp - addr].istaint++;
                                       ptag_dst[pfunc->rsp - addr].file_taint->m[tag_sprint(t)] = 1;
                                }
				fl = 1;
			}else{
				if(no <= limit_offset && no > 0){
					Taint<std::string>* tstore = new Taint<std::string>(tag_sprint(t));
					ptag_dst[pfunc->rsp - addr].file_taint = tstore;
					ptag_dst[pfunc->rsp - addr].istaint = 1;
					ptag_dst[pfunc->rsp-addr].file_taint->m[tag_sprint(t)] = 1;
					fl = 1;
				}else{
					Taint<std::string>* tstore = new Taint<std::string>(std::string("{}"));
					ptag_dst[pfunc->rsp - addr].file_taint = tstore;
					ptag_dst[pfunc->rsp - addr].istaint = 0;
				}
		
			}	
		}
		ptag_dst[pfunc->rsp - addr].dflag = ptag_src[0].dflag;
		ptag_dst[pfunc->rsp - addr].size = ptag_src[0].size;
		if ((ptag_src[0].base_addr < pfunc->rsp)&&(ptag_src[0].base_addr > 0)){
			ptag_dst[pfunc->rsp - addr].base_addr = pfunc->rsp - ptag_src[0].base_addr;
		}
		else{
			ptag_dst[pfunc->rsp - addr].base_addr = 0;
		}
	}
	to_store[pfunc->addr] = fl;
}

static void PIN_FAST_ANALYSIS_CALL
call_handler(THREADID tid, UINT64 rsp_value, ADDRINT callsite, ADDRINT target)
{
	TAG_TYPE *ctag, *ptag;
	rt_ctx_t* newFunc;
	ADDRINT root;
	
	if (tagmap_testb(target)){
		ctag = tagmap_get_ref(target);
		if (TEST_MASK(ctag->cflag, FUNC_ENTRY_MASK)){
			//LOG(StringFromAddrint(rsp_value) + " " + StringFromAddrint(callsite) + " " + StringFromAddrint(target) + "\n");
			root = rsp_value - 8;
			newFunc = (rt_ctx_t*)malloc(sizeof(rt_ctx_t));
			newFunc->type = FUNC_CTX_TYPE;
			newFunc->rsp = root;
			newFunc->addr = target;
			newFunc->callsite = callsite;
			list_add(&(newFunc->rt_stack), &(threads_ctx[tid].rt_stack_head));
			// Set up the root
			tagmap_clrn(root,8);
			ptag = tagmap_get_ref(root+7);
			ptag->base_addr = root;
			ptag->dflag = ACCESS_MASK | WRITE_MASK;
			ptag->size = 8;
			// Set up rsp
			ptag = &(threads_ctx[tid].vcpu.gpr[DFT_REG_RSP]);
			r_clr(tid, DFT_REG_RSP);
			ptag->base_addr = root;
			ptag->isPointer = TRUE;
			ptag->dflag = SET_MASK(ptag->dflag, POINTER_MASK);
			ptag->temp_base = root;
			load_taint(root, ctag);
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL
return_handler(THREADID tid, UINT64 rsp_value, ADDRINT retsite, ADDRINT target)
{
	TAG_TYPE *ptag;
	rt_ctx_t* pFunc;
	list_head_t *iter;
//	LOG("Return " + StringFromAddrint(retsite) + " " + StringFromAddrint(rsp_value) + " " + StringFromAddrint(target) + "\n");
	iter = threads_ctx[tid].rt_stack_head.next;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		pFunc = list_entry(iter, rt_ctx_t, rt_stack);
		if ((pFunc->rsp == rsp_value)&&(pFunc->type == FUNC_CTX_TYPE)){
			break;
		}
		iter = iter->next;
	}

	if (iter == &(threads_ctx[tid].rt_stack_head))
		return;

	iter = iter->prev;
	while (iter != &(threads_ctx[tid].rt_stack_head)){
		pFunc = list_entry(iter, rt_ctx_t, rt_stack);
		iter = iter->prev;
		list_del(&(pFunc->rt_stack));
		if (pFunc->type == FUNC_CTX_TYPE){
			store_taint(tid, pFunc);
			int64_t diff = pFunc->rsp - threads_ctx[tid].lowest_rsp + 1;
			if(diff > 0)
				tagmap_clrn(threads_ctx[tid].lowest_rsp, pFunc->rsp + 8 - threads_ctx[tid].lowest_rsp);
			threads_ctx[tid].lowest_rsp = pFunc->rsp + 8;
		}
		if (pFunc->type == LOOP_CTX_TYPE){
			sync_loop(tid, pFunc);
		}
		free(pFunc);
	}
	assert(!list_empty(&(threads_ctx[tid].rt_stack_head)));

	//Now find the matches and clean up space
	pFunc = list_entry(threads_ctx[tid].rt_stack_head.next,rt_ctx_t, rt_stack);
	list_del(&(pFunc->rt_stack));
	store_taint(tid, pFunc);
	tagmap_clrn(threads_ctx[tid].lowest_rsp, pFunc->rsp + 8 - threads_ctx[tid].lowest_rsp);
	threads_ctx[tid].lowest_rsp = pFunc->rsp + 8;
	free(pFunc);

	//reset rsp
	ptag = &(threads_ctx[tid].vcpu.gpr[DFT_REG_RSP]);
	r_clr(tid, DFT_REG_RSP);
	if (!list_empty(&(threads_ctx[tid].rt_stack_head))){
		pFunc = list_entry(threads_ctx[tid].rt_stack_head.next, rt_ctx_t, rt_stack);
		ptag->base_addr = pFunc->rsp;
		ptag->temp_base = pFunc->rsp;
	}
	else{
		ptag->base_addr = 0x7fffffffffff;
		ptag->temp_base = ptag->base_addr;
	}
	ptag->isPointer = TRUE;
	ptag->dflag = SET_MASK(ptag->dflag, POINTER_MASK);
}

static inline rt_ctx_t* create_loop_ctx(THREADID tid, ADDRINT ip, UINT64 rsp)
{
	rt_ctx_t* newloop;
	TAG_TYPE* ptag;

	threads_ctx[tid].rid += 1;
	newloop = (rt_ctx_t*)malloc(sizeof(rt_ctx_t));
	newloop->type = LOOP_CTX_TYPE;
	ptag = tagmap_get_ref(ip);
	newloop->sid = ptag->sid;
	newloop->rsp = rsp;
	newloop->rid = threads_ctx[tid].rid;
	newloop->iterations = 0;
	newloop->dmaps = new std::vector<std::set<UINT64>* >;
	list_add(&(newloop->rt_stack),&(threads_ctx[tid].rt_stack_head));
	return newloop;
}

static void push_loop(THREADID tid, ADDRINT ip, UINT64 rsp, TAG_TYPE* ctag)
{
	rt_ctx_t* newloop;

	if (list_empty(&(threads_ctx[tid].rt_stack_head))){
		newloop = create_loop_ctx(tid, ip, rsp);
	}
	else{
		newloop = list_entry(threads_ctx[tid].rt_stack_head.next,rt_ctx_t, rt_stack);
		if ((newloop->type != LOOP_CTX_TYPE)||(newloop->sid!=ctag->sid)){
			newloop = create_loop_ctx(tid, ip, rsp);
		}
	}
	newloop->iterations ++;
	if (newloop->iterations > newloop->dmaps->capacity())
		newloop->dmaps->resize((newloop->dmaps->capacity()+1)*2);
	newloop->dmaps->at(newloop->iterations - 1) = new std::set<UINT64>;
}

static BOOL IsLoop(ADDRINT ip, rt_ctx_t* pSite)
{
	TAG_TYPE *ctag;
	
	if (tagmap_testb(ip))
	{
		ctag = tagmap_get_ref(ip);
		if (TEST_MASK(ctag->cflag, LOOP_ENTRY_MASK)){
			if (pSite->sid == ctag->sid)
				return TRUE;
		}
		if (TEST_MASK(ctag->cflag, LOOP_BODY_MASK)){
			if (pSite->sid == ctag->body_sid)
				return TRUE;
		}
	}
	return FALSE;
}

static void popUntilFunc(THREADID tid){
	rt_ctx_t* ploop;
	list_head_t *iter;

	iter = threads_ctx[tid].rt_stack_head.next;
	if (!iter)
		return;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		ploop = list_entry(iter, rt_ctx_t, rt_stack);
		if (ploop->type == FUNC_CTX_TYPE)
			return;
		iter = iter->next;
		list_del(&(ploop->rt_stack));
		sync_loop(tid, ploop);
		free(ploop);
	}
}

static void pop_loop(THREADID tid, ADDRINT ip, UINT64 rsp, TAG_TYPE* ctag)
{
	rt_ctx_t* ploop;
	list_head_t *iter;

	iter = threads_ctx[tid].rt_stack_head.next;
	while (iter!=&(threads_ctx[tid].rt_stack_head)){
		ploop = list_entry(iter, rt_ctx_t, rt_stack);
		if (ploop->type == FUNC_CTX_TYPE)
			return;
		if (IsLoop(ip, ploop))
			return;
		iter = iter->next;
		list_del(&(ploop->rt_stack));
		sync_loop(tid, ploop);
		free(ploop);
	}
}

static void PIN_FAST_ANALYSIS_CALL
update_rsp(THREADID tid, ADDRINT ip, UINT64 rsp, char* str, const CONTEXT *ctxt)
{
	TAG_TYPE *ctag;

	DEBUG_IP = ip;
	
	//TAG_TYPE *ptag;
/*        ptag = tagmap_get_ref(0x0000000000668548);
	if(ptag != NULL){
		tag_t t = file_tagmap_getb(0x0000000000668548);
		LOG(tag_sprint(t) + " " + decstr(ptag->istaint) + " " + std::string(str) + "\n");
	}*/


	
	if (ip == EXEC_ENTRY){
		threads_ctx[tid].highest_rsp = rsp;
		TRACKING = TRUE;
	}

	if (rsp < threads_ctx[tid].lowest_rsp)
		threads_ctx[tid].lowest_rsp = rsp;
	if (tagmap_testb(ip)){
		ctag = tagmap_get_ref(ip);
		if (TEST_MASK(ctag->cflag, LOOP_BODY_MASK)){
			pop_loop(tid, ip, rsp,ctag);
		}
		if (TEST_MASK(ctag->cflag, LOOP_ENTRY_MASK)){
			push_loop(tid, ip, rsp,ctag);
		}
		if (!TEST_MASK(ctag->cflag, LOOP_ENTRY_MASK)&&!TEST_MASK(ctag->cflag,LOOP_BODY_MASK))
			popUntilFunc(tid);
	}
	
	/*if ((TRACKING)||(DEBUG_LIB)){
		UINT64 val = PIN_GetContextReg(ctxt, REG_RAX);
	}*/
	
	/*if (TRACKING){
		sanity_check(tid, ctxt);
	}*/
}

static void PIN_FAST_ANALYSIS_CALL
merge_type_inst(THREADID tid, ADDRINT addr, ADDRINT rip)
{
	TAG_TYPE* tag;
	heap_ctx_t* hctx;
	rt_ctx_t *sctx;

	if ((addr >= threads_ctx[tid].lowest_rsp)&&(addr < threads_ctx[tid].highest_rsp))
		return;
	if (!list_empty(&threads_ctx[tid].rt_stack_head)){
		sctx = list_entry(threads_ctx[tid].rt_stack_head.next, rt_ctx_t, rt_stack);
		if (sctx->type != LOOP_CTX_TYPE){
			return;
		}
	}
	tag = tagmap_get_ref(addr);
	if (tag == NULL)
		return;
	if (TEST_MASK((tag->dflag), POINTER_MASK)){
		PIN_MutexLock(&HeapLock);
		hctx = heap_lookup(addr);
		if (hctx != NULL){
			PIN_MutexLock(&MergeLock);
			fprintf(fMergeLog,"<INS> %lx:%lx%lx%lx%lx+%lx\n",rip,hctx->md5.d[0],hctx->md5.d[1],
					hctx->md5.d[2],hctx->md5.d[3],addr-hctx->start);
			PIN_MutexUnlock(&MergeLock);
		}
		PIN_MutexUnlock(&HeapLock);
	}
}

static void PIN_FAST_ANALYSIS_CALL
merge_type_val_pre(THREADID tid, ADDRINT addr, ADDRINT ip)
{
	threads_ctx[tid].wopnd_mem = addr;
}

static void PIN_FAST_ANALYSIS_CALL
merge_type_val_post(THREADID tid)
{
	ADDRINT src_addr, dst_addr;
	heap_ctx_t* hctx, *hctx_src;
	rt_ctx_t* pfunc;
	EXCEPTION_INFO einfo;

	src_addr = threads_ctx[tid].wopnd_mem;
	dst_addr = 0;
	if (tagmap_testb(src_addr) == 0)
		goto err_handler;

	if (PIN_SafeCopyEx(&dst_addr,(void*)src_addr, sizeof(UINT64), &einfo) != sizeof(UINT64)||(dst_addr == 0))
		goto err_handler;
	if ((dst_addr > threads_ctx[tid].lowest_rsp)&&(dst_addr < threads_ctx[tid].highest_rsp))
		goto err_handler;
	PIN_MutexLock(&HeapLock);
	hctx = heap_lookup(dst_addr);
	if ((hctx==NULL)||(dst_addr!=hctx->start))
		goto err_handler;
	pfunc = func_lookup(tid, src_addr);
	PIN_MutexLock(&MergeLock);
	if (pfunc != NULL){
		fprintf(fMergeLog,"<VAL> %lx+%lx", pfunc->addr, pfunc->rsp-src_addr);
	}
	else{
		hctx_src = heap_lookup(src_addr);
		if (hctx_src != NULL){
			fprintf(fMergeLog,"<VAL> %lx%lx%lx%lx+%lx",
				hctx_src->md5.d[0],hctx_src->md5.d[1], hctx_src->md5.d[2], hctx_src->md5.d[3], src_addr - hctx_src->start);
		}
		else{
			fprintf(fMergeLog,"<VAL> %lx+0",src_addr);
		}
	}
	fprintf(fMergeLog,":%lx%lx%lx%lx\n",hctx->md5.d[0],hctx->md5.d[1], hctx->md5.d[2], hctx->md5.d[3]);
	PIN_MutexUnlock(&MergeLock);
err_handler:
	PIN_MutexUnlock(&HeapLock);
	return;
}



/* For File Taint Functions */


static void
deref_reg(THREADID tid, const CONTEXT* ctxt,
                UINT32 reg, UINT32 len,
                BOOL isRead, bool ismov){
        if(isRead && !ismov){
                int sz = 0;
                int prev = -1;
                uint32_t mi = UINT_MAX;
                std::vector<tag_t> src_tag(len);
                get_array_reg(tid, reg, len, src_tag);
                for(uint32_t i=0;i<len;i++){
                        tag_t t = src_tag[i];
                        tag_t::const_iterator it = t.begin();
                        if(t.numberOfOnes() == 1){
                                if(prev == -1 || (*it+1 == (uint32_t)prev) || (*it-1 == (uint32_t)prev)){
                                        prev = *it;
                                        mi = std::min(mi,(uint32_t)prev);
                                        sz++;
                                }else{
                                        //fl = 0;
                                        break;
                                }
                        }else{
                                //fl = 0;
                                break;
                        }
                }
                if(sz != 0){
                        if(file_offsets.find(std::make_pair(mi,sz)) == file_offsets.end()){
                                file_offsets[std::make_pair(mi,sz)] = 1;
                        }else{
                                file_offsets[std::make_pair(mi,sz)]++;
                        }
                }
        }
}


void
ins_inspect(INS ins)
{
	/* 
	 * temporaries;
	 * source and destination registers
	 */
	BOOL opnd_write;
	/* use XED to decode the instruction and extract its opcode */
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
	char* cstr;
	int read_counter;
	
	cstr = new char [INS_Disassemble(ins).size()+1];
	strcpy(cstr, INS_Disassemble(ins).c_str());

	/* sanity check */
	if (unlikely(ins_indx <= XED_ICLASS_INVALID || 
				ins_indx >= XED_ICLASS_LAST)) {
		fprintf(stderr,"%s:%u: unknown opcode(opcode=%d)",
			__func__, __LINE__, ins_indx);

		/* done */
		return;
	}

	if (INS_IsNop(ins))
		return;

	INS_InsertCall(ins,
		IPOINT_BEFORE,
		AFUNPTR(update_rsp),
		IARG_FAST_ANALYSIS_CALL,
		IARG_THREAD_ID,
		IARG_INST_PTR,
		IARG_REG_VALUE, REG_RSP,
		IARG_PTR, cstr,
		IARG_CONTEXT,
		IARG_END);

        bool is_mov = 0;
	switch(ins_indx){
		case XED_ICLASS_MOV:
		case XED_ICLASS_MOVDQU:
		case XED_ICLASS_MOVDQA:
		case XED_ICLASS_PMOVMSKB:
		case XED_ICLASS_PCMPEQB:
			is_mov = 1;
			break;
		default:{
			if(INS_IsMov(ins) == 1){
				is_mov = 1;
			}else{
				is_mov = 0;
			}
			break;
		}
	}
     
	
	read_counter = 0;
	for (unsigned int i=0; i< INS_OperandCount(ins); i++){
		if (INS_OperandIsMemory(ins, i)){
			if (INS_OperandRead(ins, i)){
				read_counter++;
				INS_InsertCall(ins, 
					IPOINT_BEFORE,
					AFUNPTR(deref_mem),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					(read_counter==1)?IARG_MEMORYREAD_EA:IARG_MEMORYREAD2_EA,
					IARG_UINT32, INS_OperandMemoryBaseReg(ins, i),
					IARG_UINT32, INS_OperandMemoryIndexReg(ins, i),
					IARG_UINT32, INS_OperandWidth(ins, i)/ MEM_BYTE_LEN,
					IARG_BOOL, TRUE,
					IARG_UINT32, INS_RepCountRegister(ins),
					IARG_BOOL, INS_HasRealRep(ins),
					IARG_FIRST_REP_ITERATION,
					IARG_INST_PTR,
					IARG_BOOL, is_mov,
					IARG_END);
			}
			else{
				INS_InsertCall(ins, 
					IPOINT_BEFORE,
					AFUNPTR(deref_mem),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, INS_OperandMemoryBaseReg(ins, i),
					IARG_UINT32, INS_OperandMemoryIndexReg(ins, i),
					IARG_UINT32, INS_OperandWidth(ins, i)/ MEM_BYTE_LEN,
					IARG_BOOL, FALSE,
					IARG_UINT32, INS_RepCountRegister(ins),
					IARG_BOOL, INS_HasRealRep(ins),
					IARG_FIRST_REP_ITERATION,
					IARG_INST_PTR,
					IARG_BOOL, is_mov,
					IARG_END);
			}
		}else{
                                if (INS_OperandRead(ins, i)){
                                        REG reg = INS_OperandReg(ins, i);
                                        UINT32 size = get_reg_size(reg);
                                        //read_counter++;
                                        INS_InsertCall(ins,
                                                        IPOINT_BEFORE,
                                                        AFUNPTR(deref_reg),
                                                        IARG_FAST_ANALYSIS_CALL,
                                                        IARG_THREAD_ID,
                                                        IARG_CONTEXT,
                                                        IARG_UINT32, REG_INDX(reg),
                                                        IARG_UINT32, size,
                                                        IARG_BOOL, TRUE,
                                                        IARG_BOOL, is_mov,
                                                        IARG_END);
                                }
		}
	}
	
	/* analyze the instruction */
	switch (ins_indx) {
		case XED_ICLASS_CALL_NEAR:
		{
			//LOG(INS_Disassemble(ins) + " " + decstr(INS_OperandWidth(ins, OP_0)) +  "\n");
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(call_handler),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_REG_VALUE, REG_RSP,
				IARG_INST_PTR,
				IARG_BRANCH_TARGET_ADDR,
				IARG_END);
			break;
		}
		
		case XED_ICLASS_RET_NEAR:
		{
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(return_handler),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_REG_VALUE, REG_RSP,
				IARG_INST_PTR,
				IARG_BRANCH_TARGET_ADDR,
				IARG_END);
			break;
		}
		
		case XED_ICLASS_PUSH:
		{
			if ((INS_OperandWidth(ins, OP_0) < MEM_64BIT_LEN)||
				(INS_OperandIsImmediate(ins, OP_0))){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(m_clrn_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
					IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(push_mem_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYREAD_EA,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			}
			else if (INS_OperandIsReg(ins, OP_0)){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(push_reg_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_MEMORYWRITE_EA,
					IARG_END);
			}
			break;
		}
		case XED_ICLASS_POP:
		{
			if (INS_OperandWidth(ins, OP_0) < MEM_64BIT_LEN){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(m_clrn_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
					IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(pop_mem_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYREAD_EA,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			}
			else if (INS_OperandIsReg(ins, OP_0)){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(pop_reg_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		}
		case XED_ICLASS_LEA:
		{
			if (INS_OperandWidth(ins, OP_0) < MEM_64BIT_LEN){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_END);
			}
			else{
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(reg_record),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_UINT32, INS_OperandMemoryBaseReg(ins, OP_1),
					IARG_UINT32, 0,
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(reg_record),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_UINT32, INS_OperandMemoryIndexReg(ins, OP_1),
					IARG_UINT32, 1,
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(reg_record),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_UINT32, INS_OperandReg(ins, OP_0),
					IARG_UINT32, 2,
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_AFTER,
					AFUNPTR(sync_opnd_after),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_UINT32, 0,
					IARG_END);
			}
			break;
		}
		case XED_ICLASS_INC:
		case XED_ICLASS_DEC:
		{
			if (INS_OperandWidth(ins, OP_0)<MEM_64BIT_LEN){
//			 length small than pointer clean 
				if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN+7,
						IARG_END);
				}
			}
			else{
				if (INS_OperandIsMemory(ins, OP_0)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(mem_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, 0,
							IARG_END);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(imm_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, 0,
							IARG_UINT32, 1,
							IARG_END);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(mem_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 2,
							IARG_END);
						INS_InsertCall(ins,
							IPOINT_AFTER,
							AFUNPTR(sync_opnd_after),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_CONTEXT,
							IARG_UINT32, 0,
							IARG_END);
				}
			}
			break;
		}
		case XED_ICLASS_ADC:
		case XED_ICLASS_ADD:
		case XED_ICLASS_SUB:
		case XED_ICLASS_SBB:
		case XED_ICLASS_AND:
		case XED_ICLASS_OR:
		case XED_ICLASS_XOR:
		{
			if (INS_OperandWidth(ins, OP_0)<MEM_64BIT_LEN){
//			 length small than pointer clean 
				if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
						IARG_END);
				}
			}
			else{
				// record the operand and sync afterwards 
				//LOG(INS_Disassemble(ins)+" "  + decstr(INS_OperandWidth(ins, OP_1))+"\n");

				for (int i=0;i<=OP_1;i++)
				{
					opnd_write = FALSE;
					if (INS_OperandWritten(ins, i)){
						opnd_write = TRUE;
					}
					if (INS_OperandIsReg(ins, i)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(reg_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_CONTEXT,
							IARG_UINT32, UINT32(INS_OperandReg(ins, i)),
							IARG_UINT32, i,
							IARG_END);
						if (opnd_write){
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								AFUNPTR(reg_record),
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_CONTEXT,
								IARG_UINT32, UINT32(INS_OperandReg(ins, i)),
								IARG_UINT32, 2,
								IARG_END);
						}
					}
					else if (INS_OperandIsMemory(ins, i)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(mem_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, i,
							IARG_END);
						if (opnd_write){
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								AFUNPTR(mem_record),
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_MEMORYWRITE_EA,
								IARG_UINT32, 2,
								IARG_END);
						}
					}
					else{
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(imm_record),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, INS_OperandImmediate(ins, i),
							IARG_UINT32, i,
							IARG_END);
					}
				}
				INS_InsertCall(ins,
					IPOINT_AFTER,
					AFUNPTR(sync_opnd_after),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_UINT32, 0,
					IARG_END);
			}

			break;
		}
		case XED_ICLASS_MOV:
		case XED_ICLASS_MOVNTI:
		{
			/* when dest smaller than 64 */
			if (INS_OperandWidth(ins, OP_0)<MEM_64BIT_LEN){
				if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
						IARG_END);
				}
			}
			else{
				// src = reg, dst = reg 
				if (INS_OperandIsReg(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				// src = reg, dst = mem 
				else if (INS_OperandIsMemory(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_MEMORYWRITE_EA,
						IARG_CONTEXT,
						IARG_END);
				}
				// src = mem, dst = reg 
				else if (INS_OperandIsMemory(ins, OP_1)&&(INS_OperandIsReg(ins, OP_0))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				else if (INS_OperandIsMemory(ins, OP_0)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN+7,
						IARG_END);
				}
				else if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
			}
			break;
		}
		/* conditional movs */
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
		{
			/* when dest smaller than 64 */
			if (INS_OperandWidth(ins, OP_0)<MEM_64BIT_LEN){
				if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				else{
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
						IARG_END);
				}
			}
			else{
				// src = reg, dst = reg 
				if (INS_OperandIsReg(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				// src = reg, dst = mem 
				else if (INS_OperandIsMemory(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_MEMORYWRITE_EA,
						IARG_CONTEXT,
						IARG_END);
				}
				// src = mem, dst = reg 
				else if (INS_OperandIsMemory(ins, OP_1)&&(INS_OperandIsReg(ins, OP_0))){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				else if (INS_OperandIsMemory(ins, OP_0)){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m_clrn_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN+7,
						IARG_END);
				}
				else if (INS_OperandIsReg(ins, OP_0)){
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
			}
			break;
		}
		case XED_ICLASS_AAA:
		case XED_ICLASS_AAD:
		case XED_ICLASS_AAM:
		case XED_ICLASS_AAS:
		case XED_ICLASS_CBW:
		case XED_ICLASS_CWDE:
		case XED_ICLASS_IN:
		case XED_ICLASS_LAHF:
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, DFT_REG_RAX,
					IARG_END);
			break;
		}

		case XED_ICLASS_CWD:
		case XED_ICLASS_CDQ:
		case XED_ICLASS_RDMSR:
		case XED_ICLASS_RDPMC:
		case XED_ICLASS_RDTSC:
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, DFT_REG_RAX,
					IARG_END);
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, DFT_REG_RDX,
					IARG_END);
			break;
		}
		case XED_ICLASS_BSF:
		case XED_ICLASS_BSR:
		case XED_ICLASS_BTC:
		case XED_ICLASS_BTS:
		case XED_ICLASS_BTR:
		case XED_ICLASS_CVTSD2SI:
		case XED_ICLASS_CVTSS2SI:
		case XED_ICLASS_CVTTSD2SI:
		case XED_ICLASS_CVTTSS2SI:
		case XED_ICLASS_LAR:
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_END);
			break;
		}
		case XED_ICLASS_BSWAP:
                {
			
                        INS_InsertCall(ins,
                                        IPOINT_BEFORE,
                                        AFUNPTR(r_clr_fast),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_THREAD_ID,
                                        IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
                                        IARG_END);

			break;
                }
		case XED_ICLASS_MOVZX:
		case XED_ICLASS_MOVSX:
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_END);
			break;
		}
		case XED_ICLASS_DIV:
		case XED_ICLASS_IDIV:
		case XED_ICLASS_MUL:
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, DFT_REG_RAX,
					IARG_END);
			if (INS_OperandWidth(ins, OP_0) > MEM_BYTE_LEN)
			{
				INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, DFT_REG_RDX,
						IARG_END);
			}
			break;
		}
		case XED_ICLASS_IMUL:
		{
			/* only one operand*/
			if (INS_OperandCount(ins) == 1){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, DFT_REG_RAX,
					IARG_END);
				if (INS_OperandWidth(ins, OP_0) > MEM_BYTE_LEN)
				{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clr_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, DFT_REG_RDX,
						IARG_END);
				}
			}
			else{
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_END);
			}
			break;
		}

		case XED_ICLASS_NOT:
		case XED_ICLASS_ROR:
		case XED_ICLASS_RCR:
		case XED_ICLASS_ROL:
		case XED_ICLASS_RCL:
		case XED_ICLASS_SALC:
		case XED_ICLASS_SAR:
		case XED_ICLASS_SHL:
		case XED_ICLASS_SHR:
		case XED_ICLASS_SHLD:
		case XED_ICLASS_SHRD:
		{
			if (INS_OperandIsMemory(ins, OP_0)){
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(m_clrn_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN + 7,
					IARG_END);
			}
			else{
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clr_fast),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
					IARG_END);
			}
			break;
		}
		case XED_ICLASS_ENTER:
		case XED_ICLASS_LEAVE:
			break;
		case XED_ICLASS_XCHG:
		{
			if (INS_OperandWidth(ins, OP_0) < MEM_64BIT_LEN){
				for (unsigned int i=0; i< INS_OperandCount(ins); i++){
					if (INS_OperandWritten(ins, i)){
						if (INS_OperandIsMemory(ins, i)){
							INS_InsertCall(ins, 
								IPOINT_BEFORE,
								AFUNPTR(m_clrn_fast),
								IARG_FAST_ANALYSIS_CALL,
								IARG_MEMORYWRITE_EA,
								IARG_UINT32, INS_OperandWidth(ins, i)/MEM_BYTE_LEN + 7,
								IARG_END);
						}
						else{
							INS_InsertCall(ins, 
								IPOINT_BEFORE,
								AFUNPTR(r_clr_fast),
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(INS_OperandReg(ins, i)),
								IARG_END);
						}
					}
				}
			}
			else{
				// src = reg, dst = reg 
				if (INS_OperandIsReg(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_END);
				}
				// src = reg, dst = mem 
				else if (INS_OperandIsMemory(ins, OP_0)&&(INS_OperandIsReg(ins, OP_1))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_1)),
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_MEMORYWRITE_EA,
						IARG_CONTEXT,
						IARG_END);
				}
				// src = mem, dst = reg 
				else if (INS_OperandIsMemory(ins, OP_1)&&(INS_OperandIsReg(ins, OP_0))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_set_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, DFT_REG_HELPER1,
						IARG_MEMORYWRITE_EA,
						IARG_CONTEXT,
						IARG_END);
				}

			}
			break;
		}
		default:{
			//LOG(INS_Disassemble(ins) + "\n");
			// Clear reg/mem if they are target
			for (unsigned int i=0; i< INS_OperandCount(ins); i++){
				if (INS_OperandWritten(ins, i)){
					if (INS_OperandIsMemory(ins, i)){
						INS_InsertCall(ins, 
							IPOINT_BEFORE,
							AFUNPTR(m_clrn_fast),
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, INS_OperandWidth(ins, i)/MEM_BYTE_LEN + 7,
							IARG_END);
					}
					else{
						INS_InsertCall(ins, 
							IPOINT_BEFORE,
							AFUNPTR(r_clr_fast),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(INS_OperandReg(ins, i)),
							IARG_END);
					}
				}
			}
			break;
		}
	}
	REG reg_dst, reg_src, reg_base, reg_indx;
	switch (ins_indx) {
		case XED_ICLASS_ADC:
		case XED_ICLASS_ADD:
		case XED_ICLASS_AND:
		case XED_ICLASS_OR:
		case XED_ICLASS_XOR:
		case XED_ICLASS_SBB:
		case XED_ICLASS_SUB:
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrq,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
				else if (REG_is_gr32(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrl,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
				else if (REG_is_gr16(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrw,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r2r_binary_opw,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_UINT32, REG_INDX(reg_src),
								IARG_END);
					}
				}
				else {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
						if (REG_is_Upper8(reg_dst))
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrb_u,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
						else 
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrb_l,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					}
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}

			break;
		case XED_ICLASS_BSF:
		case XED_ICLASS_BSR:
		case XED_ICLASS_MOV:
			if (INS_OperandIsImmediate(ins, OP_1) ||
				(INS_OperandIsReg(ins, OP_1) &&
				REG_is_seg(INS_OperandReg(ins, OP_1)))) {
				if (INS_OperandIsMemory(ins, OP_0)) {
					switch (INS_OperandWidth(ins, OP_0)) {
						case MEM_64BIT_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 8,
							IARG_END);
							break;
						case MEM_LONG_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 4,
							IARG_END);
							break;
						case MEM_WORD_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 2,
							IARG_END);

							break;
						case MEM_BYTE_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 1,
							IARG_END);

							break;
						default:
						LOG(string(__func__) +
						": unhandled operand width (" +
						INS_Disassemble(ins) + ")\n");


							return;
					}
				}
				else if (INS_OperandIsReg(ins, OP_0)) {
					reg_dst = INS_OperandReg(ins, OP_0);
					if (REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_gr16(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_Upper8(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_u,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_l,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}
			}
			else if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst)) 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);

				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}

			break;
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				if (REG_is_gr64(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_CBW:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opb_ul,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AH),
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_END);

			break;
		case XED_ICLASS_CWD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_DX),
				IARG_UINT32, REG_INDX(REG_AX),
				IARG_END);

			break;
		case XED_ICLASS_CWDE:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)_cwde,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);
			break;
		case XED_ICLASS_CDQ:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EDX),
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_END);

			break;
		case XED_ICLASS_CDQE:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)_cdqe,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);
			break;
		case XED_ICLASS_CQO:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EDX),
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_END);

			break;
/*		case XED_ICLASS_MOVSX:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr16(reg_dst)) {
					if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);

				}
				else if (REG_is_Upper8(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opqb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
			}
			break;
		case XED_ICLASS_MOVSXD:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_r2r_opql,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_m2r_opql,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVZX:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				if (REG_is_gr16(reg_dst)) {
					if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_Upper8(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opqb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
			}
			break;
		*/
                case XED_ICLASS_MOVZX:
                case XED_ICLASS_MOVSX:
                case XED_ICLASS_MOVSXD:
                        if(INS_OperandIsReg(ins, OP_0)){
                                REG reg_dest = INS_OperandReg(ins, OP_0);
                                uint32_t size_dest = get_reg_size(reg_dest);
                                if(INS_OperandIsReg(ins, OP_1)){
                                        REG reg_src = INS_OperandReg(ins, OP_1);
                                        uint32_t size_src = get_reg_size(reg_src);
                                        INS_InsertCall(ins,
                                                        IPOINT_BEFORE,
                                                        AFUNPTR(file_r2r_lea),
                                                        IARG_FAST_ANALYSIS_CALL,
                                                        IARG_THREAD_ID,
                                                        IARG_UINT32, REG_INDX(reg_dest),
                                                        IARG_UINT32, REG_INDX(reg_src),
                                                        IARG_UINT32, size_dest,
                                                        IARG_UINT32, size_src,
                                                        IARG_END);
                                }else if(INS_OperandIsMemory(ins, OP_1)){
                                        uint32_t size_src = INS_OperandWidth(ins, OP_1)/MEM_BYTE_LEN;
                                        INS_InsertCall(ins,
                                                        IPOINT_BEFORE,
                                                        AFUNPTR(file_m2r_movzx),
                                                        IARG_FAST_ANALYSIS_CALL,
                                                        IARG_THREAD_ID,
                                                        IARG_UINT32, REG_INDX(reg_dest),
                                                        IARG_MEMORYREAD_EA,
                                                        IARG_UINT32, size_dest,
                                                        IARG_UINT32, size_src,
                                                        IARG_END);
                                }
                        }
                        break;
        case XED_ICLASS_SHL:
                if(INS_OperandIsMemory(ins, OP_0)){
                        if(INS_OperandIsReg(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shlm),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_MEMORYWRITE_EA,
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                                                IARG_END);
                        }else if(INS_OperandIsImmediate(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shlm),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_MEMORYWRITE_EA,
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_UINT32, INS_OperandImmediate(ins, OP_1),
                                                IARG_END);
                        }
                }else if(INS_OperandIsReg(ins, OP_0)){
                        if(INS_OperandIsReg(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shlr),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_THREAD_ID,
                                                IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                                                IARG_END);
                        }else if(INS_OperandIsImmediate(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shlr),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_THREAD_ID,
                                                IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_UINT32, INS_OperandImmediate(ins, OP_1),
                                                IARG_END);
                        }
                }
                break;
        case XED_ICLASS_SHR:
        case XED_ICLASS_SAR:
                if(INS_OperandIsMemory(ins, OP_0)){
                        if(INS_OperandIsReg(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shrm),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_MEMORYWRITE_EA,
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                                                IARG_END);
                        }else if(INS_OperandIsImmediate(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shrm),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_MEMORYWRITE_EA,
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_UINT32, INS_OperandImmediate(ins, OP_1),
                                                IARG_END);
                        }
                }else if(INS_OperandIsReg(ins, OP_0)){
                        if(INS_OperandIsReg(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shrr),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_THREAD_ID,
                                                IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                                                IARG_END);
                        }else if(INS_OperandIsImmediate(ins, OP_1)){
                                INS_InsertCall(ins,
                                                IPOINT_BEFORE,
                                                AFUNPTR(file_shrr),
                                                IARG_FAST_ANALYSIS_CALL,
                                                IARG_THREAD_ID,
                                                IARG_UINT32, REG_INDX(INS_OperandReg(ins, OP_0)),
                                                IARG_UINT32, INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN,
                                                IARG_UINT32, INS_OperandImmediate(ins, OP_1),
                                                IARG_END);
                        }
                }
                break;
                case XED_ICLASS_BSWAP:{
                        REG reg_dest = INS_OperandReg(ins, OP_0);
                        uint32_t size = get_reg_size(reg_dest);
                        INS_InsertCall(ins,
                                        IPOINT_BEFORE,
                                        AFUNPTR(file_bswap),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_THREAD_ID,
                                        IARG_UINT32, REG_INDX(reg_dest),
                                        IARG_UINT32, size,
                                        IARG_END);
                        break;
                }
		case XED_ICLASS_DIV:
		case XED_ICLASS_IDIV:
		case XED_ICLASS_MUL:
			if (INS_OperandIsMemory(ins, OP_0))
				switch (INS_MemoryWriteSize(ins)) {
					case BIT2BYTE(MEM_64BIT_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_LONG_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_WORD_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);

						break;
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
				}
			else {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			break;
		case XED_ICLASS_IMUL:
			if (INS_OperandIsImplicit(ins, OP_1)) {
				if (INS_OperandIsMemory(ins, OP_0))
				switch (INS_MemoryWriteSize(ins)) {
					case BIT2BYTE(MEM_64BIT_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_LONG_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_WORD_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);

						break;
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
				}
			else {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				if (INS_OperandIsImmediate(ins, OP_1))
					break;

				if (INS_MemoryOperandCount(ins) == 0) {
					reg_dst = INS_OperandReg(ins, OP_0);
					reg_src = INS_OperandReg(ins, OP_1);
				
					if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
				}
				else {
					reg_dst = INS_OperandReg(ins, OP_0);
					if (REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
					else if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
				}
			}

			break;
		case XED_ICLASS_SETB:
		case XED_ICLASS_SETBE:
		case XED_ICLASS_SETL:
		case XED_ICLASS_SETLE:
		case XED_ICLASS_SETNB:
		case XED_ICLASS_SETNBE:
		case XED_ICLASS_SETNL:
		case XED_ICLASS_SETNLE:
		case XED_ICLASS_SETNO:
		case XED_ICLASS_SETNP:
		case XED_ICLASS_SETNS:
		case XED_ICLASS_SETNZ:
		case XED_ICLASS_SETO:
		case XED_ICLASS_SETP:
		case XED_ICLASS_SETS:
		case XED_ICLASS_SETZ:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_Upper8(reg_dst))	
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else 
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			else
				INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)file_tagmap_clrn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, 1,
					IARG_END);

			break;
		case XED_ICLASS_STMXCSR:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 4,
				IARG_END);
		
			/* done */
			break;
		case XED_ICLASS_SMSW:
		case XED_ICLASS_STR:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)file_tagmap_clrn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, 2,
					IARG_END);

			break;

		case XED_ICLASS_LAR:
			reg_dst = INS_OperandReg(ins, OP_0);

			if (REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			else if (REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			else if (REG_is_gr64(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			break;
		case XED_ICLASS_RDPMC:
		case XED_ICLASS_RDTSC:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl2,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			break;
		case XED_ICLASS_CPUID:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl4,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			break;
		case XED_ICLASS_LAHF:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_u,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AH),
				IARG_END);

			break;
		case XED_ICLASS_CMPXCHG:
			//LOG("Compare class" +  INS_Disassemble(ins) + "\n");
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opq_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opq_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else
				LOG(string(__func__) +
					": unhandled opcode (opcode=" +
					decstr(ins_indx) + ")\n");
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opq_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opq_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else
				LOG(string(__func__) +
					": unhandled opcode (opcode=" +
					decstr(ins_indx) + ")\n");
			}
			break;

		case XED_ICLASS_CMP:{
//				LOG(" CMP " + StringFromAddrint(INS_Address(ins)) + " " + INS_Disassemble(ins) + "\n");
				if(INS_OperandIsReg(ins, OP_0)){
					REG reg_dest = INS_OperandReg(ins, OP_0);
					uint32_t size = get_reg_size(reg_dest);
					if(INS_OperandIsReg(ins, OP_1)){
						REG reg_src = INS_OperandReg(ins, OP_1);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_r2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_UINT32, REG_INDX(reg_src),
							IARG_REG_VALUE, reg_src,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsMemory(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_m2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsImmediate(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_i2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_UINT32, INS_OperandImmediate(ins, OP_1),
							IARG_UINT32, size,
							IARG_END);
					}
				}else if(INS_OperandIsMemory(ins, OP_0)){
					uint32_t size = INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN;
					if(INS_OperandIsReg(ins, OP_1)){
						REG reg_src = INS_OperandReg(ins, OP_1);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_r2m),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, REG_INDX(reg_src),
							IARG_REG_VALUE, reg_src,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsImmediate(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_i2m),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, INS_OperandImmediate(ins, OP_1),
							IARG_UINT32, size,
							IARG_END);
					}
				}
			break;	
		}
                case XED_ICLASS_CMPSB:{
//                      	LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 1,
                                IARG_END);

                	break;
        	}
                case XED_ICLASS_CMPSW:{
//                        LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 2,
                                IARG_END);

        	        break;
        	}
                case XED_ICLASS_CMPSD:{
//                        LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 4,
                                IARG_END);

               		break;
        	}
               case XED_ICLASS_CMPSQ:{
//              	          LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 8,
                                IARG_END);

                	break;
        	}

		case XED_ICLASS_XCHG:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_XADD:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
						
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_XLAT:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSB:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSW:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSD:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSQ:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_STOSB:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opbn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opb_l,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_AL),
					IARG_END);

			break;
		case XED_ICLASS_STOSW:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opwn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_AX),
					IARG_END);

			break;
		case XED_ICLASS_STOSD:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opln,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_EAX),
					IARG_END);

			break;
		case XED_ICLASS_STOSQ:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opqn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_EAX),
					IARG_END);

			break;

		case XED_ICLASS_MOVSQ:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSD:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSW:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSB:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_SALC:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_END);

			break;
		case XED_ICLASS_RCL:
		case XED_ICLASS_RCR:
		case XED_ICLASS_ROL:
		case XED_ICLASS_ROR:
		case XED_ICLASS_SHRD:

			break;
		case XED_ICLASS_POP:
			if (INS_OperandIsReg(ins, OP_0)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)) {
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);

				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_PUSH:
			if (INS_OperandIsReg(ins, OP_0)) {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)) {
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				switch (INS_OperandWidth(ins, OP_0)) {
					case MEM_64BIT_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
						break;
					case MEM_LONG_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
						break;
					case MEM_WORD_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);

						break;
					case MEM_BYTE_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 1,
						IARG_END);
						break;
					default:
						break;
				}
			}
			break;
		case XED_ICLASS_POPA:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_POPAD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHA:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHAD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHF:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 2,
				IARG_END);

			break;
		case XED_ICLASS_PUSHFD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 4,
				IARG_END);

			break;
		case XED_ICLASS_PUSHFQ:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 8,
				IARG_END);

			break;
		case XED_ICLASS_CALL_NEAR:
			if (INS_OperandIsImmediate(ins, OP_0)) {
				if (INS_OperandWidth(ins, OP_0) == MEM_64BIT_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}
			else if (INS_OperandIsReg(ins, OP_0)) {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}
			else {

				if (INS_OperandWidth(ins, OP_0) == MEM_64BIT_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}

			break;
		case XED_ICLASS_LEAVE:
			reg_dst = INS_OperandReg(ins, OP_3);
			reg_src = INS_OperandReg(ins, OP_2);
			if (REG_is_gr64(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			else if (REG_is_gr32(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}

			break;
		case XED_ICLASS_LEA:
			reg_base	= INS_MemoryBaseReg(ins);
			reg_indx	= INS_MemoryIndexReg(ins);
			reg_dst		= INS_OperandReg(ins, OP_0);
			
			if (reg_base == REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			if (reg_base != REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
			}
			if (reg_base == REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
			}
			if (reg_base != REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
			}			
			break;
		case XED_ICLASS_MOVAPS:
		case XED_ICLASS_MOVDQA:
		case XED_ICLASS_MOVDQU:
			if (INS_MemoryOperandCount(ins) == 0) { 
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);				
			}else if(INS_OperandIsReg(ins, OP_0)){
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}else{
				reg_src = INS_OperandReg(ins, OP_1); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVD:
		case XED_ICLASS_MOVQ:
			if (INS_MemoryOperandCount(ins) == 0) { 
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1); 
				if(REG_is_xmm(reg_dst)){
					if(REG_is_gr64(reg_src))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}else if(REG_is_xmm(reg_src)){
					if(REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}		
			}
			else if(INS_OperandIsReg(ins, OP_0)){
				reg_dst = INS_OperandReg(ins, OP_0); 
				if (INS_MemoryReadSize(ins) == BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}else{
				reg_src = INS_OperandReg(ins, OP_1); 
				if (INS_MemoryReadSize(ins) == BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			break;
		case XED_ICLASS_MOVLPD:
		case XED_ICLASS_MOVLPS:
			if (INS_OperandIsMemory(ins, OP_0)){
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				
			}else{
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVHPD:
		case XED_ICLASS_MOVHPS:
			if (INS_OperandIsMemory(ins, OP_0)){
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq_h,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				
			}else{
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq_h,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_ADDPS:
		case XED_ICLASS_ANDNPS:
		case XED_ICLASS_ANDPS:
		case XED_ICLASS_ORPS:
		case XED_ICLASS_PXOR:
		case XED_ICLASS_POR:
		case XED_ICLASS_PSUBB:
		case XED_ICLASS_PSUBW:
		case XED_ICLASS_PSUBD:
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_xmm(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_PXOR:
						case XED_ICLASS_PSUBB:
						case XED_ICLASS_PSUBW:
						case XED_ICLASS_PSUBD:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrx,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r2r_binary_opx,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_UINT32, REG_INDX(reg_src),
								IARG_END);
					}
				}else{
					switch (ins_indx) {
						case XED_ICLASS_PXOR:
						case XED_ICLASS_PSUBB:
						case XED_ICLASS_PSUBW:
						case XED_ICLASS_PSUBD:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrq,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
			}else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_xmm(reg_dst)){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opx,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
			}
			break;

		case XED_ICLASS_CMPXCHG8B:
		case XED_ICLASS_ENTER:
			LOG(string(__func__) +
				": unhandled opcode (opcode=" +
				decstr(ins_indx) + ")\n");

			break;
		default:
			break;
	}

		
	//For merge
/*	read_counter = 0;
	for (unsigned int i=0; i< INS_OperandCount(ins); i++){
		if (INS_OperandIsMemory(ins, i)){
			if (INS_OperandRead(ins, i)){
				read_counter++;
				if (INS_OperandWidth(ins, i) == MEM_64BIT_LEN){
					INS_InsertCall(ins, 
						IPOINT_BEFORE,
						AFUNPTR(merge_type_inst),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						(read_counter==1)?IARG_MEMORYREAD_EA:IARG_MEMORYREAD2_EA,
						IARG_INST_PTR,
						IARG_END);
				}
			}
			else{
				if ((INS_OperandWidth(ins, i)==MEM_64BIT_LEN)&&(INS_HasFallThrough(ins))){
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(merge_type_val_pre),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR,
						IARG_END);
					INS_InsertCall(ins, 
						IPOINT_AFTER,
						AFUNPTR(merge_type_val_post),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_END);
				}
			}
		}
	}*/
/*	if(flag == 1){
	//LOG(INS_Disassemble(ins)+ " " + StringFromAddrint(INS_Address(ins)) + "\n");
   read_counter = 0;
   for (unsigned int i=0; i< INS_OperandCount(ins); i++){

 		//LOG(INS_Disassemble(ins)+ " " + StringFromAddrint(INS_Address(ins)) + "\n");
                uint32_t opnd_size = INS_OperandWidth(ins,i)/MEM_BYTE_LEN;
                if (INS_OperandIsReg(ins, i) && REG_INDX(INS_OperandReg(ins,i)) != GRP_NUM){
                        if (INS_OperandRead(ins, i)){
                                INS_InsertCall(ins,
                                        IPOINT_BEFORE,
                                        AFUNPTR(show_taint_reg),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_THREAD_ID,
                                        IARG_UINT32, REG_INDX(INS_OperandReg(ins, i)),
                                        IARG_UINT32, opnd_size,
			                IARG_PTR, cstr,
                                        IARG_BOOL, false,
					IARG_REG_VALUE, INS_OperandReg(ins, i),
                                        IARG_END);
                        };
                        if (INS_OperandWritten(ins, i)){
                                INS_InsertCall(ins,
                                        IPOINT_BEFORE,
                                        AFUNPTR(show_taint_reg),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_THREAD_ID,
                                        IARG_UINT32, REG_INDX(INS_OperandReg(ins, i)),
                                        IARG_UINT32, opnd_size,
			                IARG_PTR, cstr,
                                        IARG_BOOL, true,
					IARG_REG_VALUE, INS_OperandReg(ins, i),
                                        IARG_END);
                        }
                }else if (INS_OperandIsMemory(ins, i)){
			if (INS_OperandRead(ins, i)){
				read_counter++;
					INS_InsertCall(ins, 
						IPOINT_BEFORE,
						AFUNPTR(show_taint_mem),
						IARG_FAST_ANALYSIS_CALL,
						(read_counter==1)?IARG_MEMORYREAD_EA:IARG_MEMORYREAD2_EA,
                                        	IARG_UINT32, opnd_size,
			                	IARG_PTR, cstr,
                                        	IARG_BOOL, false,
						IARG_END);
			}
			else{
				INS_InsertCall(ins, 
						IPOINT_BEFORE,
						AFUNPTR(show_taint_mem),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
                                        	IARG_UINT32, opnd_size,
			                	IARG_PTR, cstr,
                                        	IARG_BOOL, true,
						IARG_END);
			}
		}

        }
	}*/
}



