#ifndef __LIBCALL_DESC_H__
#define __LIBCALL_DESC_H__

#include "libdft_api.h"
#include "libdft_utils.h"
#include "branch_pred.h"
#include "tagmap.h"

#define LIBCALL_LIBC         0
#define LIBCALL_LIBC_MALLOC  0
#define LIBCALL_LIBC_FREE    1
#define LIBCALL_LIBC_REALLOC 2
#define LIBCALL_LIBC_CALLOC  3

//#define LIBCALL_MAX          1241
#define LIBCALL_MAX          21

/* lib call descriptor */
typedef struct {
	const char* name;
	const char* lib;
	ADDRINT entry; /* entry address in plt table */
	int nargs; /* number of arguments */
	void (* pre)(libcall_ctx_t*);
	void (* post)(libcall_ctx_t*);
	std::string args_type[6];
	std::string ret_type;
} libcall_desc_t;


/* libcall API */
int libcall_set_pre(libcall_desc_t*, void (*)(libcall_ctx_t*));
int libcall_clr_pre(libcall_desc_t*);
int libcall_set_post(libcall_desc_t*, void (*)(libcall_ctx_t*));
int libcall_clr_post(libcall_desc_t*);

/* instrument API for libcall */
VOID libcall_img_inspect(IMG, VOID*);
VOID libcall_trace_inspect(TRACE, VOID*);

/* callbacks for outsider */
void free_callback(void);

#endif /* __LIBCALL_DESC_H__ */
