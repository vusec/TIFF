#include <string.h>
#include <map>
#include <utility>
#include <iomanip>

#include "libcall_desc.h"
#include "tagmap.h"
#include "libdft_api.h"
#include "branch_pred.h"
#include <assert.h>
#include "pin.H"

static const char* const lut = "0123456789ABCDEF";

extern thread_ctx_t *threads_ctx;
extern int flag;
std::set<std::pair<int,int> > stored;
extern std::ofstream reward_taint;

static void post_malloc_hook(libcall_ctx_t*);
//static void pre_free_hook(libcall_ctx_t*);

/*static void pre_common_hook(libcall_ctx_t*);
  static void post_common_hook(libcall_ctx_t*);*/
static void post_strcpy_hook(libcall_ctx_t*);
static void post_strncpy_hook(libcall_ctx_t*);
static void post_strtok_hook(libcall_ctx_t*);
static void post_strtok_r_hook(libcall_ctx_t*);
static void pre_rawmemchr_hook(libcall_ctx_t*);
static void pre_memchr_hook(libcall_ctx_t*);
static void post_strlen_hook(libcall_ctx_t*);
static void post_strnlen_hook(libcall_ctx_t*);
static void post_strncmp_hook(libcall_ctx_t*);
static void post_strndup_hook(libcall_ctx_t*);
static void post_strdup_hook(libcall_ctx_t*);
static void post_strcmp_hook(libcall_ctx_t*);
static void post_memset_hook(libcall_ctx_t*);
static void post_memmove_hook(libcall_ctx_t*);
static void post_memcpy_hook(libcall_ctx_t*);
static void post_memcmp_hook(libcall_ctx_t*);


map<std::string, int> type_map = {{"char*", 0}, {"char *", 0}, {"void *", 0}, {"const char *", 0}, {"const char*", 0}, {"int",1} , {"size_t",1}};
//static void post_strncpy_hook(libcall_ctx_t*);
/* libcall descriptors */
libcall_desc_t libcall_desc[LIBCALL_MAX] = {
	/*{ "pthread_key_create" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pthread_key_t *","void (*)(void*)" } , "int" } ,
	  { "pthread_key_delete" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pthread_key_t" } , "int" } ,
	  { "*pthread_getspecific" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "pthread_key_t" } , "void" } ,
	  { "pthread_setspecific" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pthread_key_t","const void *" } , "int" } ,
	  { "__ppc_get_timebase" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "uint64_t" } ,
	  { "__ppc_get_timebase_freq" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "uint64_t" } ,
	  { "__ppc_yield" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_mdoio" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_mdoom" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_set_ppr_med" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_set_ppr_low" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_set_ppr_med_low" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_set_ppr_very_low" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "__ppc_set_ppr_med_high" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "accept" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sockaddr *","socklen_t *" } , "int" } ,
	  { "abort" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	  { "flockfile" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	  { "ftrylockfile" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	  { "funlockfile" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	  { "__fsetlocking" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","int" } , "int" } ,
	  { "abs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	  { "labs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long int" } , "long int" } ,
	  { "llabs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long long int" } , "long long int" } ,
	  { "imaxabs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "intmax_t" } , "intmax_t" } ,
	  { "fabs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "fabsf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "fabsl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "cabs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "double" } ,
	  { "cabsf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "float" } ,
	  { "cabsl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "long double" } ,
	  { "l64a" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long int" } , "char *" } ,
	  { "a64l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "long int" } ,
	  { "sinh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "sinhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "sinhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "cosh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "coshf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "coshl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "tanh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "tanhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "tanhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "csinh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	  { "csinhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	  { "csinhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	  { "ccosh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	  { "asin" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "asinf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "asinl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "acos" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "acosf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "acosl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "atan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "atanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "atanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "atan2" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	  { "atan2f" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	  { "atan2l" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	  { "casin" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	  { "ccoshf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	  { "ccoshl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	  { "ctanh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	  { "ctanhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	  { "ctanhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	  { "asinh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "asinhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "asinhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "acosh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "acoshf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	  { "acoshl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	  { "atanh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	  { "atanhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "atanhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "casinh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "casinf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "casinl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "cacos" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "cacosf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "cacosl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "catan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "catanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "catanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "access" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "int" } ,
	{ "casinhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "casinhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "cacosh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "cacoshf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "cacoshl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "catanh" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "catanhf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "catanhl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "fopen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "FILE *" } ,
	{ "fopen64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "FILE *" } ,
	{ "freopen" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","FILE *" } , "FILE *" } ,
	{ "freopen64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","FILE *" } , "FILE *" } ,
	{ "__freadable" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "__fwritable" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "__freading" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "__fwriting" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "setvbuf" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "FILE *","char *","int","size_t" } , "int" } ,
	{ "setbuf" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "FILE *","char *" } , "void" } ,
	{ "setbuffer" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "FILE *","char *","size_t" } , "void" } ,
	{ "setlinebuf" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	{ "__flbf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "__fbufsize" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "size_t" } ,
	{ "__fpending" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "size_t" } ,
	{ "fflush" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fflush_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "_flushlbf" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "__fpurge" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	{ "tolower" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "toupper" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "toascii" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "_tolower" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "_toupper" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sched_setscheduler" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "pid_t","int","const struct sched_param *" } , "int" } ,
	{ "sched_getscheduler" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pid_t" } , "int" } ,
	{ "sched_setparam" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","const struct sched_param *" } , "int" } ,
	{ "sched_getparam" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","struct sched_param *" } , "int" } ,
	{ "sched_get_priority_min" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sched_get_priority_max" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sched_rr_get_interval" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","struct timespec *" } , "int" } ,
	{ "sched_yield" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "wordexp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","wordexp_t *","int" } , "int" } ,
	{ "wordfree" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "wordexp_t *" } , "void" } ,
	{ "_exit" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "_Exit" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "wait3" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int *","int","struct rusage *" } , "pid_t" } ,
	{ "waitpid" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "pid_t","int *","int" } , "pid_t" } ,
	{ "wait" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int *" } , "pid_t" } ,
	{ "wait4" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "pid_t","int *","int","struct rusage *" } , "pid_t" } ,
	{ "ungetc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "ungetwc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wint_t","FILE *" } , "wint_t" } ,
	{ "vscanf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","va_list" } , "int" } ,
	{ "vwscanf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","va_list" } , "int" } ,
	{ "vfscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const char *","va_list" } , "int" } ,
	{ "vfwscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const wchar_t *","va_list" } , "int" } ,
	{ "vsscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","va_list" } , "int" } ,
	{ "vswscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *","va_list" } , "int" } ,
	{ "tzset" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "wctrans" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "wctrans_t" } ,
	{ "towctrans" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wint_t","wctrans_t" } , "wint_t" } ,
	{ "towlower" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "wint_t" } ,
	{ "towupper" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "wint_t" } ,
	{ "uname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct utsname *" } , "int" } ,
	{ "times" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct tms *" } , "clock_t" } ,
	{ "tsearch" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","void **","comparison_fn_t" } , "void *" } ,
	{ "tfind" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","void *const *","comparison_fn_t" } , "void *" } ,
	{ "tdelete" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","void **","comparison_fn_t" } , "void *" } ,
	{ "tdestroy" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "void *","__free_fn_t" } , "void" } ,
	{ "twalk" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const void *","__action_fn_t" } , "void" } ,
	{ "tcgetpgrp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "pid_t" } ,
	{ "tcsetpgrp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","pid_t" } , "int" } ,
	{ "tcgetsid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "pid_t" } ,
	{ "tcgetattr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct termios *" } , "int" } ,
	{ "tcsetattr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","const struct termios *" } , "int" } ,
	{ "tcsendbreak" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "tcdrain" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "tcflush" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "tcflow" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "system" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "syslog" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","..." } , "void" } ,
	{ "vsyslog" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","va_list" } , "void" } ,
	{ "sysctl" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "int *","int","void *","size_t *","void *","size_t" } , "int" } ,
	{ "sysconf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "long int" } ,
	{ "syscall" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long int","..." } , "long int" } ,
	{ "strlen" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "size_t" } ,
	{ "wcslen" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const wchar_t *" } , "size_t" } ,
	{ "strnlen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "size_t" } ,
	{ "wcsnlen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","size_t" } , "size_t" } ,
	{ "strptime" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","struct tm *" } , "char *" } ,
	{ "strfry" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "strcoll" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "wcscoll" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "int" } ,
	{ "strxfrm" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","size_t" } , "size_t" } ,
	{ "wcsxfrm" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "size_t" } ,
	{ "strcat" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","const char *" } , "char *" } ,
	{ "wcscat" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "time" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "time_t *" } , "time_t" } ,
	{ "stime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const time_t *" } , "int" } ,
	{ "socket" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","int" } , "int" } ,
	{ "strncpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","size_t" } , "char *" } ,
	{ "wcsncpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "strndup" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "char *" } ,
	{ "stpncpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","size_t" } , "char *" } ,
	{ "wcpncpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "strncat" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","size_t" } , "char *" } ,
	{ "wcsncat" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "socketpair" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","int","int","int [2]" } , "int" } ,
	{ "sigsuspend" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const sigset_t *" } , "int" } ,
	{ "sigprocmask" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const sigset_t *","sigset_t *" } , "int" } ,
	{ "sigpending" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sigset_t *" } , "int" } ,
	{ "signal" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","sighandler_t" } , "sighandler_t" } ,
	{ "sysv_signal" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","sighandler_t" } , "sighandler_t" } ,
	{ "ssignal" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","sighandler_t" } , "sighandler_t" } ,
	{ "sigsetjmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "sigjmp_buf","int" } , "int" } ,
	{ "siglongjmp" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "sigjmp_buf","int" } , "void" } ,
	{ "siginterrupt" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "sigblock" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sigsetmask" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sigpause" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "sigemptyset" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sigset_t *" } , "int" } ,
	{ "sigfillset" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sigset_t *" } , "int" } ,
	{ "sigaddset" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "sigset_t *","int" } , "int" } ,
	{ "sigdelset" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "sigset_t *","int" } , "int" } ,
	{ "sigismember" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const sigset_t *","int" } , "int" } ,
	{ "sigaltstack" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const stack_t *","stack_t *" } , "int" } ,
	{ "sigstack" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct sigstack *","struct sigstack *" } , "int" } ,
	{ "sigaction" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const struct sigaction *","struct sigaction *" } , "int" } ,
	{ "shutdown" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "setlogmask" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "setlocale" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const char *" } , "char *" } ,
	{ "send" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","const void *","size_t","int" } , "ssize_t" } ,
	{ "sendto" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "int","const void *","size_t","int","struct sockaddr *","socklen_t" } , "ssize_t" } ,
	{ "seteuid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uid_t" } , "int" } ,
	{ "setuid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uid_t" } , "int" } ,
	{ "setreuid" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "uid_t","uid_t" } , "int" } ,
	{ "rewinddir" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "DIR *" } , "void" } ,
	{ "telldir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "DIR *" } , "long int" } ,
	{ "seekdir" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "DIR *","long int" } , "void" } ,
	{ "rpmatch" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "strfmon" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","size_t","const char *","..." } , "ssize_t" } ,
	{ "rename" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "unlink" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "rmdir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "remove" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "register_printf_function" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","printf_function","printf_arginfo_function" } , "int" } ,
	{ "regexec" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const regex_t *","const char *","size_t","regmatch_t []","int" } , "int" } ,
	{ "regfree" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "regex_t *" } , "void" } ,
	{ "regerror" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","const regex_t *","char *","size_t" } , "size_t" } ,
	{ "recvfrom" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "int","void *","size_t","int","struct sockaddr *","socklen_t *" } , "ssize_t" } ,
	{ "regcomp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "regex_t *","const char *","int" } , "int" } ,
	{ "realloc" , "libc.so.6" , 0 , 2 , NULL , NULL , { "void *","size_t" } , "void *" } ,
	{ "recv" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","void *","size_t","int" } , "ssize_t" } ,
	{ "readv" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const struct iovec *","int" } , "ssize_t" } ,
	{ "writev" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const struct iovec *","int" } , "ssize_t" } ,
	{ "rand" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "srand" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "unsigned int" } , "void" } ,
	{ "rand_r" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned int *" } , "int" } ,
	{ "qsort" , "libc.so.6" , 0 , 4 , pre_common_hook , NULL , { "void *","size_t","size_t","comparison_fn_t" } , "void" } ,
	{ "putpwent" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct passwd *","FILE *" } , "int" } ,
	{ "pthread_getattr_default_np" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pthread_attr_t *" } , "int" } ,
	{ "pthread_setattr_default_np" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pthread_attr_t *" } , "int" } ,
	{ "strsignal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "char *" } ,
	{ "psignal" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "int","const char *" } , "void" } ,
	{ "printf_size" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const struct printf_info *","const void *const *" } , "int" } ,
	{ "printf_size_info" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const struct printf_info *","size_t","int *" } , "int" } ,
	{ "pipe" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int [2]" } , "int" } ,
	{ "posix_fallocate" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","off_t","off_t" } , "int" } ,
	{ "posix_fallocate64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","off64_t","off64_t" } , "int" } ,
	{ "popen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "FILE *" } ,
	{ "pclose" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "read" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","void *","size_t" } , "ssize_t" } ,
	{ "pread" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","void *","size_t","off_t" } , "ssize_t" } ,
	{ "pread64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","void *","size_t","off64_t" } , "ssize_t" } ,
	{ "write" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const void *","size_t" } , "ssize_t" } ,
	{ "pwrite" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","const void *","size_t","off_t" } , "ssize_t" } ,
	{ "pwrite64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","const void *","size_t","off64_t" } , "ssize_t" } ,
	{ "pause" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "parse_printf_format" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","size_t","int *" } , "size_t" } ,
	{ "openlog" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const char *","int","int" } , "void" } ,
	{ "vprintf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","va_list" } , "int" } ,
	{ "vwprintf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","va_list" } , "int" } ,
	{ "vfprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const char *","va_list" } , "int" } ,
	{ "vfwprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const wchar_t *","va_list" } , "int" } ,
	{ "vsprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","va_list" } , "int" } ,
	{ "vswprintf" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "wchar_t *","size_t","const wchar_t *","va_list" } , "int" } ,
	{ "vsnprintf" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","size_t","const char *","va_list" } , "int" } ,
	{ "vasprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","const char *","va_list" } , "int" } ,
	{ "obstack_vprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "struct obstack *","const char *","va_list" } , "int" } ,
	{ "obstack_free" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","void *" } , "void" } ,
	{ "obstack_init" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "int" } ,
	{ "obstack_base" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "void *" } ,
	{ "obstack_next_free" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "void *" } ,
	{ "obstack_object_size" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "int" } ,
	{ "obstack_alloc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct obstack *","int" } , "void *" } ,
	{ "obstack_copy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "struct obstack *","void *","int" } , "void *" } ,
	{ "obstack_copy0" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "struct obstack *","void *","int" } , "void *" } ,
	{ "obstack_room" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "int" } ,
	{ "obstack_1grow_fast" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","char" } , "void" } ,
	{ "obstack_ptr_grow_fast" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","void *" } , "void" } ,
	{ "obstack_int_grow_fast" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","int" } , "void" } ,
	{ "obstack_blank_fast" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","int" } , "void" } ,
	{ "obstack_blank" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","int" } , "void" } ,
	{ "obstack_grow" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "struct obstack *","void *","int" } , "void" } ,
	{ "obstack_grow0" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "struct obstack *","void *","int" } , "void" } ,
	{ "obstack_1grow" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","char" } , "void" } ,
	{ "obstack_ptr_grow" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","void *" } , "void" } ,
	{ "obstack_int_grow" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "struct obstack *","int" } , "void" } ,
	{ "obstack_finish" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "void *" } ,
	{ "obstack_object_size" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct obstack *" } , "int" } ,
	{ "ntp_gettime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct ntptimeval *" } , "int" } ,
	{ "ntp_adjtime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct timex *" } , "int" } ,
	{ "sleep" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned int" } , "unsigned int" } ,
	{ "nanosleep" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct timespec *","struct timespec *" } , "int" } ,
	{ "mtrace" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "muntrace" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "mount" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const char *","const char *","const char *","unsigned long int","const void *" } , "int" } ,
	{ "umount2" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "int" } ,
	{ "umount" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "mlock" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const void *","size_t" } , "int" } ,
	{ "munlock" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const void *","size_t" } , "int" } ,
	{ "mlockall" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "munlockall" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "mknod" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","mode_t","dev_t" } , "int" } ,
	{ "mkfifo" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","mode_t" } , "int" } ,
	{ "tmpfile" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "FILE *" } ,
	{ "tmpfile64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "FILE *" } ,
	{ "tmpnam" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "tmpnam_r" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "tempnam" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "mktemp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "mkstemp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "int" } ,
	{ "mkdtemp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "mkdir" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","mode_t" } , "int" } ,
	{ "memfrob" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "void *","size_t" } , "void *" } ,
	{ "mcheck" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void (*) (enum mcheck_status )" } , "int" } ,
	{ "mprobe" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void *" } , "enum mcheck_status" } ,
	{ "mbstowcs" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const char *","size_t" } , "size_t" } ,
	{ "wcstombs" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const wchar_t *","size_t" } , "size_t" } ,
	{ "mbsinit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const mbstate_t *" } , "int" } ,
	{ "mbsrtowcs" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "wchar_t *","const char **","size_t","mbstate_t *" } , "size_t" } ,
	{ "wcsrtombs" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","const wchar_t **","size_t","mbstate_t *" } , "size_t" } ,
	{ "mbsnrtowcs" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "wchar_t *","const char **","size_t","size_t","mbstate_t *" } , "size_t" } ,
	{ "wcsnrtombs" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "char *","const wchar_t **","size_t","size_t","mbstate_t *" } , "size_t" } ,
	{ "mbtowc" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const char *","size_t" } , "int" } ,
	{ "wctomb" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","wchar_t" } , "int" } ,
	{ "mblen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "int" } ,
	{ "mallopt" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "nl_langinfo" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "nl_item" } , "char *" } ,
	{ "malloc" , "libc.so.6" , 0 , 1 , NULL , post_malloc_hook , { "size_t" } , "void *" } ,
	{ "mallinfo" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct mallinfo" } ,
	{ "lseek" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","off_t","int" } , "off_t" } ,
	{ "lseek64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","off64_t","int" } , "off64_t" } ,
	{ "mmap" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "void *","size_t","int","int","int","off_t" } , "void *" } ,
	{ "mmap64" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "void *","size_t","int","int","int","off64_t" } , "void *" } ,
	{ "munmap" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "void *","size_t" } , "int" } ,
	{ "msync" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","size_t","int" } , "int" } ,
	{ "mremap" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "void *","size_t","size_t","int" } , "void *" } ,
	{ "madvise" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","size_t","int" } , "int" } ,
	{ "shm_open" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","int","mode_t" } , "int" } ,
	{ "shm_unlink" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "longjmp" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "jmp_buf","int" } , "void" } ,
	{ "login_tty" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "login" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "const struct utmp *" } , "void" } ,
	{ "logout" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "logwtmp" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const char *","const char *","const char *" } , "void" } ,
	{ "localeconv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct lconv *" } ,
	{ "listen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "link" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "kill" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","int" } , "int" } ,
	{ "killpg" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "wctype" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "wctype_t" } ,
	{ "iswctype" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wint_t","wctype_t" } , "int" } ,
	{ "iswalnum" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswalpha" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswcntrl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswdigit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswgraph" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswlower" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswprint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswpunct" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswspace" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswupper" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswxdigit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "iswblank" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "islower" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isupper" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isalpha" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isdigit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isalnum" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isxdigit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "ispunct" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isspace" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isblank" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isgraph" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isprint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "iscntrl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isascii" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "isatty" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "ttyname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "char *" } ,
	{ "ttyname_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","char *","size_t" } , "int" } ,
	{ "ioctl" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","..." } , "int" } ,
	{ "innetgr" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","const char *","const char *","const char *" } , "int" } ,
	{ "random" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "srandom" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "unsigned int" } , "void" } ,
	{ "initstate" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "unsigned int","char *","size_t" } , "char *" } ,
	{ "setstate" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "random_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct random_data *","int32_t *" } , "int" } ,
	{ "srandom_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "unsigned int","struct random_data *" } , "int" } ,
	{ "initstate_r" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "unsigned int","char *","size_t","struct random_data *" } , "int" } ,
	{ "setstate_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","struct random_data *" } , "int" } ,
	{ "inet_aton" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct in_addr *" } , "int" } ,
	{ "inet_addr" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "uint32_t" } ,
	{ "inet_network" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "uint32_t" } ,
	{ "inet_ntoa" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct in_addr" } , "char *" } ,
	{ "inet_makeaddr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "uint32_t","uint32_t" } , "struct in_addr" } ,
	{ "inet_lnaof" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct in_addr" } , "uint32_t" } ,
	{ "inet_netof" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct in_addr" } , "uint32_t" } ,
	{ "inet_pton" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const char *","void *" } , "int" } ,
	{ "inet_ntop" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","const void *","char *","socklen_t" } , "const char *" } ,
	{ "memchr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","int","size_t" } , "void *" } ,
	{ "wmemchr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t","size_t" } , "wchar_t *" } ,
	{ "rawmemchr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const void *","int" } , "void *" } ,
	{ "memrchr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","int","size_t" } , "void *" } ,
	{ "strchr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "char *" } ,
	{ "wcschr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","int" } , "wchar_t *" } ,
	{ "strchrnul" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "char *" } ,
	{ "wcschrnul" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","wchar_t" } , "wchar_t *" } ,
	{ "strrchr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "char *" } ,
	{ "wcsrchr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","wchar_t" } , "wchar_t *" } ,
	{ "strstr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "wcsstr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "wcswcs" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "strcasestr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "memmem" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const void *","size_t","const void *","size_t" } , "void *" } ,
	{ "strspn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "size_t" } ,
	{ "wcsspn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "size_t" } ,
	{ "strcspn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "size_t" } ,
	{ "wcscspn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "size_t" } ,
	{ "strpbrk" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "wcspbrk" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "index" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "char *" } ,
	{ "rindex" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "char *" } ,
	{ "if_nametoindex" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "unsigned int" } ,
	{ "if_indextoname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "unsigned int","char *" } , "char *" } ,
	{ "if_nameindex" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct if_nameindex *" } ,
	{ "if_freenameindex" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "struct if_nameindex *" } , "void" } ,
	{ "iconv_open" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "iconv_t" } ,
	{ "iconv_close" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "iconv_t" } , "int" } ,
	{ "iconv" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "iconv_t","char **","size_t *","char **","size_t *" } , "size_t" } ,
	{ "htons" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uint16_t" } , "uint16_t" } ,
	{ "ntohs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uint16_t" } , "uint16_t" } ,
	{ "htonl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uint32_t" } , "uint32_t" } ,
	{ "ntohl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uint32_t" } , "uint32_t" } ,
	{ "gtty" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct sgttyb *" } , "int" } ,
	{ "stty" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const struct sgttyb *" } , "int" } ,
	{ "hcreate" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "size_t" } , "int" } ,
	{ "hdestroy" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "hsearch" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "ENTRY","ACTION" } , "ENTRY *" } ,
	{ "hcreate_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "size_t","struct hsearch_data *" } , "int" } ,
	{ "hdestroy_r" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "struct hsearch_data *" } , "void" } ,
	{ "hsearch_r" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "ENTRY","ACTION","ENTRY **","struct hsearch_data *" } , "int" } ,
	{ "raise" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "gsignal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "globfree" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "glob_t *" } , "void" } ,
	{ "globfree64" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "glob64_t *" } , "void" } ,
	{ "getsubopt" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","char *const *","char **" } , "int" } ,
	{ "glob" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","int","int (*) (const char *, int )","glob_t *" } , "int" } ,
	{ "glob64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","int","int (*) (const char *, int )","glob64_t *" } , "int" } ,
	{ "getsockopt" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int","int","int","void *","socklen_t *" } , "int" } ,
	{ "setsockopt" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int","int","int","const void *","socklen_t" } , "int" } ,
	{ "getsockname" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sockaddr *","socklen_t *" } , "int" } ,
	{ "getrusage" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct rusage *" } , "int" } ,
	{ "vtimes" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct vtimes *","struct vtimes *" } , "int" } ,
	{ "getrlimit" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct rlimit *" } , "int" } ,
	{ "getrlimit64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct rlimit64 *" } , "int" } ,
	{ "setrlimit" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const struct rlimit *" } , "int" } ,
	{ "setrlimit64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const struct rlimit64 *" } , "int" } ,
	{ "ulimit" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","..." } , "long int" } ,
	{ "vlimit" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "getpwuid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "uid_t" } , "struct passwd *" } ,
	{ "getpwuid_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "uid_t","struct passwd *","char *","size_t","struct passwd **" } , "int" } ,
	{ "getpwnam" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct passwd *" } ,
	{ "getpwnam_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const char *","struct passwd *","char *","size_t","struct passwd **" } , "int" } ,
	{ "getpt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "grantpt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "unlockpt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "ptsname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "char *" } ,
	{ "ptsname_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","char *","size_t" } , "int" } ,
	{ "getpriority" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "setpriority" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","int" } , "int" } ,
	{ "nice" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "getpid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "getppid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "setsid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "getsid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pid_t" } , "pid_t" } ,
	{ "getpgrp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "getpgid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "pid_t" } , "int" } ,
	{ "setpgid" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","pid_t" } , "int" } ,
	{ "setpgrp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "pid_t","pid_t" } , "int" } ,
	{ "getpeername" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sockaddr *","socklen_t *" } , "int" } ,
	{ "getpass" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "getpagesize" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "get_phys_pages" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "get_avphys_pages" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "getopt" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","char *const *","const char *" } , "int" } ,
	{ "getopt_long" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int","char *const *","const char *","const struct option *","int *" } , "int" } ,
	{ "getopt_long_only" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int","char *const *","const char *","const struct option *","int *" } , "int" } ,
	{ "get_nprocs_conf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "get_nprocs" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "getloadavg" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double []","int" } , "int" } ,
	{ "localtime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const time_t *" } , "struct tm *" } ,
	{ "localtime_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const time_t *","struct tm *" } , "struct tm *" } ,
	{ "gmtime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const time_t *" } , "struct tm *" } ,
	{ "gmtime_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const time_t *","struct tm *" } , "struct tm *" } ,
	{ "mktime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct tm *" } , "time_t" } ,
	{ "timelocal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct tm *" } , "time_t" } ,
	{ "timegm" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct tm *" } , "time_t" } ,
	{ "setegid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "gid_t" } , "int" } ,
	{ "setgid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "gid_t" } , "int" } ,
	{ "setregid" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "gid_t","gid_t" } , "int" } ,
	{ "setgroups" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "size_t","const gid_t *" } , "int" } ,
	{ "initgroups" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","gid_t" } , "int" } ,
	{ "getgrouplist" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","gid_t","gid_t *","int *" } , "int" } ,
	{ "getgrgid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "gid_t" } , "struct group *" } ,
	{ "getgrgid_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "gid_t","struct group *","char *","size_t","struct group **" } , "int" } ,
	{ "getgrnam" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct group *" } ,
	{ "getgrnam_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const char *","struct group *","char *","size_t","struct group **" } , "int" } ,
	{ "getuid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "uid_t" } ,
	{ "getgid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "gid_t" } ,
	{ "geteuid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "uid_t" } ,
	{ "getegid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "gid_t" } ,
	{ "getgroups" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","gid_t *" } , "int" } ,
	{ "gethostname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","size_t" } , "int" } ,
	{ "sethostname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "int" } ,
	{ "getdomainnname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","size_t" } , "int" } ,
	{ "setdomainname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "int" } ,
	{ "gethostid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "sethostid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long int" } , "int" } ,
	{ "getdate" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct tm *" } ,
	{ "getdate_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct tm *" } , "int" } ,
	{ "getcontext" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "ucontext_t *" } , "int" } ,
	{ "makecontext" , "libc.so.6" , 0 , 4 , pre_common_hook , NULL , { "ucontext_t *","void (*) (void)","int","..." } , "void" } ,
	{ "setcontext" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const ucontext_t *" } , "int" } ,
	{ "swapcontext" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "ucontext_t *","const ucontext_t *" } , "int" } ,
	{ "getauxval" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned long int" } , "unsigned long int" } ,
	{ "fwide" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","int" } , "int" } ,
	{ "utime" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const struct utimbuf *" } , "int" } ,
	{ "utimes" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const struct timeval [2]" } , "int" } ,
	{ "lutimes" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const struct timeval [2]" } , "int" } ,
	{ "futimes" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const struct timeval [2]" } , "int" } ,
	{ "ftw" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","__ftw_func_t","int" } , "int" } ,
	{ "ftw64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","__ftw64_func_t","int" } , "int" } ,
	{ "nftw" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","__nftw_func_t","int","int" } , "int" } ,
	{ "nftw64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","__nftw64_func_t","int","int" } , "int" } ,
	{ "truncate" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","off_t" } , "int" } ,
	{ "truncate64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","off64_t" } , "int" } ,
	{ "ftruncate" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","off_t" } , "int" } ,
	{ "ftruncate64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","off64_t" } , "int" } ,
	{ "stat" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct stat *" } , "int" } ,
	{ "stat64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct stat64 *" } , "int" } ,
	{ "fstat" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct stat *" } , "int" } ,
	{ "fstat64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct stat64 *" } , "int" } ,
	{ "lstat" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct stat *" } , "int" } ,
	{ "lstat64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","struct stat64 *" } , "int" } ,
	{ "ftell" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "long int" } ,
	{ "ftello" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "off_t" } ,
	{ "ftello64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "off64_t" } ,
	{ "fseek" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","long int","int" } , "int" } ,
	{ "fseeko" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","off_t","int" } , "int" } ,
	{ "fseeko64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","off64_t","int" } , "int" } ,
	{ "rewind" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	{ "scanf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","..." } , "int" } ,
	{ "wscanf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","..." } , "int" } ,
	{ "fscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const char *","..." } , "int" } ,
	{ "fwscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const wchar_t *","..." } , "int" } ,
	{ "sscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","..." } , "int" } ,
	{ "swscanf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *","..." } , "int" } ,
	{ "frexp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","int *" } , "double" } ,
	{ "frexpf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","int *" } , "float" } ,
	{ "frexpl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","int *" } , "long double" } ,
	{ "ldexp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","int" } , "double" } ,
	{ "ldexpf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","int" } , "float" } ,
	{ "ldexpl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","int" } , "long double" } ,
	{ "scalb" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "scalbf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "scalbl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "scalbn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","int" } , "double" } ,
	{ "scalbnf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","int" } , "float" } ,
	{ "scalbnl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","int" } , "long double" } ,
	{ "scalbln" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","long int" } , "double" } ,
	{ "scalblnf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","long int" } , "float" } ,
	{ "scalblnl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long int" } , "long double" } ,
	{ "significand" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "significandf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "significandl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "fread" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "void *","size_t","size_t","FILE *" } , "size_t" } ,
	{ "fread_unlocked" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "void *","size_t","size_t","FILE *" } , "size_t" } ,
	{ "fwrite" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const void *","size_t","size_t","FILE *" } , "size_t" } ,
	{ "fwrite_unlocked" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const void *","size_t","size_t","FILE *" } , "size_t" } ,
	{ "fputc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "fputwc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t","FILE *" } , "wint_t" } ,
	{ "fputc_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "fputwc_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t","FILE *" } , "wint_t" } ,
	{ "putc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "putwc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t","FILE *" } , "wint_t" } ,
	{ "putc_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "putwc_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t","FILE *" } , "wint_t" } ,
	{ "putchar" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "putwchar" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wchar_t" } , "wint_t" } ,
	{ "putchar_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "putwchar_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wchar_t" } , "wint_t" } ,
	{ "fputs" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","FILE *" } , "int" } ,
	{ "fputws" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","FILE *" } , "int" } ,
	{ "fputs_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","FILE *" } , "int" } ,
	{ "fputws_unlocked" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","FILE *" } , "int" } ,
	{ "puts" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "putw" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","FILE *" } , "int" } ,
	{ "printf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","..." } , "int" } ,
	{ "wprintf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","..." } , "int" } ,
	{ "fprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const char *","..." } , "int" } ,
	{ "fwprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "FILE *","const wchar_t *","..." } , "int" } ,
	{ "sprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","..." } , "int" } ,
	{ "swprintf" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "wchar_t *","size_t","const wchar_t *","..." } , "int" } ,
	{ "snprintf" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","size_t","const char *","..." } , "int" } ,
	{ "pathconf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "long int" } ,
	{ "fpathconf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "long int" } ,
	{ "openpty" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int *","int *","char *","const struct termios *","const struct winsize *" } , "int" } ,
	{ "forkpty" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int *","char *","const struct termios *","const struct winsize *" } , "int" } ,
	{ "fork" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "vfork" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "pid_t" } ,
	{ "fopencookie" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","const char *","cookie_io_functions_t" } , "FILE *" } ,
	{ "fnmatch" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","int" } , "int" } ,
	{ "fmtmsg" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "long int","const char *","int","const char *","const char *","const char *" } , "int" } ,
	{ "fmemopen" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","size_t","const char *" } , "FILE *" } ,
	{ "open_memstream" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char **","size_t *" } , "FILE *" } ,
	{ "isinf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "int" } ,
	{ "isinff" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "int" } ,
	{ "isinfl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "int" } ,
	{ "isnan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "int" } ,
	{ "isnanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "int" } ,
	{ "isnanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "int" } ,
	{ "finite" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "int" } ,
	{ "finitef" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "int" } ,
	{ "finitel" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "int" } ,
	{ "getline" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","size_t *","FILE *" } , "ssize_t" } ,
	{ "getdelim" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char **","size_t *","int","FILE *" } , "ssize_t" } ,
	{ "fgets" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","int","FILE *" } , "char *" } ,
	{ "fgetws" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","int","FILE *" } , "wchar_t *" } ,
	{ "fgets_unlocked" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","int","FILE *" } , "char *" } ,
	{ "fgetws_unlocked" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","int","FILE *" } , "wchar_t *" } ,
	{ "fgetpos" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","fpos_t *" } , "int" } ,
	{ "fgetpos64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","fpos64_t *" } , "int" } ,
	{ "fsetpos" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","const fpos_t *" } , "int" } ,
	{ "fsetpos64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","const fpos64_t *" } , "int" } ,
	{ "fgetc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fgetwc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "wint_t" } ,
	{ "fgetc_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fgetwc_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "wint_t" } ,
	{ "getc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "getwc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "wint_t" } ,
	{ "getc_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "getwc_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "wint_t" } ,
	{ "getchar" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "getwchar" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "wint_t" } ,
	{ "getchar_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "getwchar_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "wint_t" } ,
	{ "getw" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "feof" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "feof_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "ferror" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "ferror_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fegetround" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "fesetround" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fegetenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "fenv_t *" } , "int" } ,
	{ "feholdexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "fenv_t *" } , "int" } ,
	{ "fesetenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const fenv_t *" } , "int" } ,
	{ "feupdateenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const fenv_t *" } , "int" } ,
	{ "feenableexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fedisableexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fegetexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "feclearexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "feraiseexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fetestexcept" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fegetexceptflag" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "fexcept_t *","int" } , "int" } ,
	{ "fesetexceptflag" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const fexcept_t *","int" } , "int" } ,
	{ "select" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "int","fd_set *","fd_set *","fd_set *","struct timeval *" } , "int" } ,
	{ "fmin" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "fminf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "fminl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "fmax" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "fmaxf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "fmaxl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "fdim" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "fdimf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "fdiml" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "fma" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "double","double","double" } , "double" } ,
	{ "fmaf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "float","float","float" } , "float" } ,
	{ "fmal" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "long double","long double","long double" } , "long double" } ,
	{ "fdopen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const char *" } , "FILE *" } ,
	{ "fileno" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fileno_unlocked" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "sync" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "fsync" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fdatasync" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "fcntl" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","..." } , "int" } ,
	{ "fclose" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "fcloseall" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "exit" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "execv" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char *const []" } , "int" } ,
	{ "execl" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","..." } , "int" } ,
	{ "execve" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char *const []","char *const []" } , "int" } ,
	{ "execle" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","const char *","...","char *const []" } , "int" } ,
	{ "execvp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char *const []" } , "int" } ,
	{ "execlp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","..." } , "int" } ,
	{ "strerror" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "char *" } ,
	{ "strerror_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","char *","size_t" } , "char *" } ,
	{ "perror" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "const char *" } , "void" } ,
	{ "error" , "libc.so.6" , 0 , 4 , pre_common_hook , NULL , { "int","int","const char *","..." } , "void" } ,
	{ "error_at_line" , "libc.so.6" , 0 , 6 , pre_common_hook , NULL , { "int","int","const char *","unsigned int","const char *","..." } , "void" } ,
	{ "warn" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","..." } , "void" } ,
	{ "vwarn" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","va_list" } , "void" } ,
	{ "warnx" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","..." } , "void" } ,
	{ "vwarnx" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","va_list" } , "void" } ,
	{ "err" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","..." } , "void" } ,
	{ "verr" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","va_list" } , "void" } ,
	{ "errx" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","..." } , "void" } ,
	{ "verrx" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "int","const char *","va_list" } , "void" } ,
	{ "erf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "erff" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "erfl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "erfc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "erfcf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "erfcl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "lgamma" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "lgammaf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "lgammal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "lgamma_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","int *" } , "double" } ,
	{ "lgammaf_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","int *" } , "float" } ,
	{ "lgammal_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","int *" } , "long double" } ,
	{ "gamma" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "gammaf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "gammal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "tgamma" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "tgammaf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "envz_entry" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","size_t","const char *" } , "char *" } ,
	{ "envz_get" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","size_t","const char *" } , "char *" } ,
	{ "envz_add" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char **","size_t *","const char *","const char *" } , "error_t" } ,
	{ "envz_merge" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "char **","size_t *","const char *","size_t","int" } , "error_t" } ,
	{ "envz_strip" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "char **","size_t *" } , "void" } ,
	{ "envz_remove" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "char **","size_t *","const char *" } , "void" } ,
	{ "tgammal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "j0" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "j0f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "j0l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "j1" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "j1f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "j1l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "jn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","double" } , "double" } ,
	{ "jnf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","float" } , "float" } ,
	{ "jnl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","long double" } , "long double" } ,
	{ "y0" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "y0f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "y0l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "y1" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "y1f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "y1l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "yn" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","double" } , "double" } ,
	{ "ynf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","float" } , "float" } ,
	{ "ynl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","long double" } , "long double" } ,
	{ "setutxent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getutxent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct utmpx *" } ,
	{ "endutxent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getutxid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmpx *" } , "struct utmpx *" } ,
	{ "getutxline" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmpx *" } , "struct utmpx *" } ,
	{ "pututxline" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmpx *" } , "struct utmpx *" } ,
	{ "utmpxname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "getutmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct utmpx *","struct utmp *" } , "int" } ,
	{ "getutmpx" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct utmp *","struct utmpx *" } , "int" } ,
	{ "setutent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getutent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct utmp *" } ,
	{ "endutent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getutid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmp *" } , "struct utmp *" } ,
	{ "getutline" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmp *" } , "struct utmp *" } ,
	{ "pututline" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct utmp *" } , "struct utmp *" } ,
	{ "getutent_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct utmp *","struct utmp **" } , "int" } ,
	{ "getutid_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const struct utmp *","struct utmp *","struct utmp **" } , "int" } ,
	{ "getutline_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const struct utmp *","struct utmp *","struct utmp **" } , "int" } ,
	{ "utmpname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "updwtmp" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","const struct utmp *" } , "void" } ,
	{ "getservbyname" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "struct servent *" } ,
	{ "getservbyport" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const char *" } , "struct servent *" } ,
	{ "setservent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "getservent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct servent *" } ,
	{ "endservent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "fgetpwent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "struct passwd *" } ,
	{ "fgetpwent_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "FILE *","struct passwd *","char *","size_t","struct passwd **" } , "int" } ,
	{ "setpwent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getpwent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct passwd *" } ,
	{ "getpwent_r" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "struct passwd *","char *","size_t","struct passwd **" } , "int" } ,
	{ "endpwent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getprotobyname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct protoent *" } ,
	{ "getprotobynumber" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "struct protoent *" } ,
	{ "setprotoent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "getprotoent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct protoent *" } ,
	{ "endprotoent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "setnetgrent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "getnetgrent" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","char **","char **" } , "int" } ,
	{ "getnetgrent_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "char **","char **","char **","char *","size_t" } , "int" } ,
	{ "endnetgrent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getnetbyname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct netent *" } ,
	{ "getnetbyaddr" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "uint32_t","int" } , "struct netent *" } ,
	{ "setnetent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "getnetent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct netent *" } ,
	{ "endnetent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "gethostbyname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct hostent *" } ,
	{ "gethostbyname2" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "struct hostent *" } ,
	{ "gethostbyaddr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","socklen_t","int" } , "struct hostent *" } ,
	{ "gethostbyname_r" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "const char *","struct hostent *","char *","size_t","struct hostent **","int *" } , "int" } ,
	{ "sethostent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "int" } , "void" } ,
	{ "gethostent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct hostent *" } ,
	{ "endhostent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "fgetgrent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "struct group *" } ,
	{ "fgetgrent_r" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "FILE *","struct group *","char *","size_t","struct group **" } , "int" } ,
	{ "setgrent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getgrent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct group *" } ,
	{ "getgrent_r" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "struct group *","char *","size_t","struct group **" } , "int" } ,
	{ "endgrent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "ecvt" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "double","int","int *","int *" } , "char *" } ,
	{ "fcvt" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "double","int","int *","int *" } , "char *" } ,
	{ "gcvt" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "double","int","char *" } , "char *" } ,
	{ "qecvt" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "long double","int","int *","int *" } , "char *" } ,
	{ "qfcvt" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "long double","int","int *","int *" } , "char *" } ,
	{ "qgcvt" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "long double","int","char *" } , "char *" } ,
	{ "ecvt_r" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "double","int","int *","int *","char *","size_t" } , "int" } ,
	{ "fcvt_r" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "double","int","int *","int *","char *","size_t" } , "int" } ,
	{ "qecvt_r" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "long double","int","int *","int *","char *","size_t" } , "int" } ,
	{ "qfcvt_r" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "long double","int","int *","int *","char *","size_t" } , "int" } ,
	{ "dup" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "dup2" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "int" } ,
	{ "setfsent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "endfsent" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "getfsent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "struct fstab *" } ,
	{ "getfsspec" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct fstab *" } ,
	{ "getfsfile" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "struct fstab *" } ,
	{ "IFTODT" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "mode_t" } , "int" } ,
	{ "DTTOIF" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "mode_t" } ,
	{ "fmod" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "fmodf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "fmodl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "drem" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "dremf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "dreml" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "remainder" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "remainderf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "remainderl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "drand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "double" } ,
	{ "erand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned short int [3]" } , "double" } ,
	{ "lrand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "nrand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned short int [3]" } , "long int" } ,
	{ "mrand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "long int" } ,
	{ "jrand48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned short int [3]" } , "long int" } ,
	{ "srand48" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "long int" } , "void" } ,
	{ "seed48" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned short int [3]" } , "unsigned short int *" } ,
	{ "lcong48" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "unsigned short int [7]" } , "void" } ,
	{ "drand48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct drand48_data *","double *" } , "int" } ,
	{ "erand48_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "unsigned short int [3]","struct drand48_data *","double *" } , "int" } ,
	{ "lrand48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct drand48_data *","long int *" } , "int" } ,
	{ "nrand48_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "unsigned short int [3]","struct drand48_data *","long int *" } , "int" } ,
	{ "mrand48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct drand48_data *","long int *" } , "int" } ,
	{ "jrand48_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "unsigned short int [3]","struct drand48_data *","long int *" } , "int" } ,
	{ "srand48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long int","struct drand48_data *" } , "int" } ,
	{ "seed48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "unsigned short int [3]","struct drand48_data *" } , "int" } ,
	{ "lcong48_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "unsigned short int [7]","struct drand48_data *" } , "int" } ,
	{ "div" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","int" } , "div_t" } ,
	{ "ldiv" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long int","long int" } , "ldiv_t" } ,
	{ "lldiv" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long long int","long long int" } , "lldiv_t" } ,
	{ "imaxdiv" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "intmax_t","intmax_t" } , "imaxdiv_t" } ,
	{ "opendir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "DIR *" } ,
	{ "fdopendir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "DIR *" } ,
	{ "dirfd" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "DIR *" } , "int" } ,
	{ "difftime" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "time_t","time_t" } , "double" } ,
	{ "ngettext" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","unsigned long int" } , "char *" } ,
	{ "dngettext" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","const char *","const char *","unsigned long int" } , "char *" } ,
	{ "dcngettext" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const char *","const char *","const char *","unsigned long int","int" } , "char *" } ,
	{ "gettext" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "dgettext" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "dcgettext" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","int" } , "char *" } ,
	{ "getlogin" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "char *" } ,
	{ "cuserid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "ctermid" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "sched_getaffinity" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "pid_t","size_t","cpu_set_t *" } , "int" } ,
	{ "sched_setaffinity" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "pid_t","size_t","const cpu_set_t *" } , "int" } ,
	{ "crypt" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "crypt_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","struct crypt_data *" } , "char *" } ,
	{ "copysign" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "copysignf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "copysignl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "signbit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float-type" } , "int" } ,
	{ "nextafter" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "nextafterf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "nextafterl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "nexttoward" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","long double" } , "double" } ,
	{ "nexttowardf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","long double" } , "float" } ,
	{ "nexttowardl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "nextup" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "nextupf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "nextupl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "nextdown" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "nextdownf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "nextdownl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "nan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "double" } ,
	{ "nanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "float" } ,
	{ "nanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "long double" } ,
	{ "connect" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sockaddr *","socklen_t" } , "int" } ,
	{ "confstr" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","char *","size_t" } , "size_t" } ,
	{ "closelog" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void" } , "void" } ,
	{ "readdir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "DIR *" } , "struct dirent *" } ,
	{ "readdir_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "DIR *","struct dirent *","struct dirent **" } , "int" } ,
	{ "readdir64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "DIR *" } , "struct dirent64 *" } ,
	{ "readdir64_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "DIR *","struct dirent64 *","struct dirent64 **" } , "int" } ,
	{ "closedir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "DIR *" } , "int" } ,
	{ "clock" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "clock_t" } ,
	{ "open" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","int [","mode_t ]" } , "int" } ,
	{ "open64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","int [","mode_t ]" } , "int" } ,
	{ "close" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "clearerr" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	{ "clearerr_unlocked" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "FILE *" } , "void" } ,
	{ "getenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "secure_getenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "putenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "int" } ,
	{ "setenv" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","int" } , "int" } ,
	{ "unsetenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "clearenv" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "int" } ,
	{ "chown" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","uid_t","gid_t" } , "int" } ,
	{ "fchown" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","uid_t","gid_t" } , "int" } ,
	{ "umask" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "mode_t" } , "mode_t" } ,
	{ "getumask" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "mode_t" } ,
	{ "chmod" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","mode_t" } , "int" } ,
	{ "fchmod" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","mode_t" } , "int" } ,
	{ "getcwd" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","size_t" } , "char *" } ,
	{ "getwd" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "get_current_dir_name" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void" } , "char *" } ,
	{ "chdir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "fchdir" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "free" , "libc.so.6" , 0 , 1 , pre_free_hook , NULL , { "void *" } , "void" } ,
	{ "cfree" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "void *" } , "void" } ,
	{ "cfmakeraw" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "struct termios *" } , "void" } ,
	{ "cfgetospeed" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct termios *" } , "speed_t" } ,
	{ "cfgetispeed" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct termios *" } , "speed_t" } ,
	{ "cfsetospeed" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct termios *","speed_t" } , "int" } ,
	{ "cfsetispeed" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct termios *","speed_t" } , "int" } ,
	{ "cfsetspeed" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct termios *","speed_t" } , "int" } ,
	{ "ceil" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "ceilf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "ceill" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "floor" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "floorf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "floorl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "trunc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "truncf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "truncl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "rint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "rintf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "rintl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "nearbyint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "nearbyintf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "nearbyintl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "round" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "roundf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "roundl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "lrint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "long int" } ,
	{ "lrintf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "long int" } ,
	{ "lrintl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long int" } ,
	{ "llrint" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "long long int" } ,
	{ "llrintf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "long long int" } ,
	{ "llrintl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long long int" } ,
	{ "lround" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "long int" } ,
	{ "lroundf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "long int" } ,
	{ "lroundl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long int" } ,
	{ "llround" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "long long int" } ,
	{ "llroundf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "long long int" } ,
	{ "llroundl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long long int" } ,
	{ "modf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double *" } , "double" } ,
	{ "modff" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float *" } , "float" } ,
	{ "modfl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double *" } , "long double" } ,
	{ "sin" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "sinf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "sinl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "cos" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "cosf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "cosl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "tan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "tanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "tanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "sincos" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "double","double *","double *" } , "void" } ,
	{ "sincosf" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "float","float *","float *" } , "void" } ,
	{ "sincosl" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "long double","long double *","long double *" } , "void" } ,
	{ "csin" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "csinf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "csinl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "ccos" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "ccosf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "ccosl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "ctan" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "ctanf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "ctanl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "exp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "expf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "expl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "exp2" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "exp2f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "exp2l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "exp10" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "exp10f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "exp10l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "pow10" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "pow10f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "pow10l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "log" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "logf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "logl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "log10" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "log10f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "log10l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "log2" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "log2f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "log2l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "logb" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "logbf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "logbl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "ilogb" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "int" } ,
	{ "ilogbf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "int" } ,
	{ "ilogbl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "int" } ,
	{ "pow" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "powf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "powl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "sqrt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "sqrtf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "sqrtl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "cbrt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "cbrtf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "cbrtl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "hypot" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "double","double" } , "double" } ,
	{ "hypotf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "float","float" } , "float" } ,
	{ "hypotl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "long double","long double" } , "long double" } ,
	{ "expm1" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "expm1f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "expm1l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "log1p" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "double" } , "double" } ,
	{ "log1pf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "float" } , "float" } ,
	{ "log1pl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "long double" } , "long double" } ,
	{ "cexp" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "cexpf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "cexpl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "clog" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "clogf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "clogl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "clog10" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "clog10f" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "clog10l" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "csqrt" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "csqrtf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "csqrtl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "cpow" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "complex double","complex double" } , "complex double" } ,
	{ "cpowf" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "complex float","complex float" } , "complex float" } ,
	{ "cpowl" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "complex long double","complex long double" } , "complex long double" } ,
	{ "setkey" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "const char *" } , "void" } ,
	{ "encrypt" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "char *","int" } , "void" } ,
	{ "setkey_r" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "const char *","struct crypt_data *" } , "void" } ,
	{ "encrypt_r" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "char *","int","struct crypt_data *" } , "void" } ,
	{ "ecb_crypt" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","char *","unsigned","unsigned" } , "int" } ,
	{ "DES_FAILED" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "int" } ,
	{ "cbc_crypt" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "char *","char *","unsigned","unsigned","char *" } , "int" } ,
	{ "des_setparity" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "char *" } , "void" } ,
	{ "catopen" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","int" } , "nl_catd" } ,
	{ "catgets" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "nl_catd","int","int","const char *" } , "char *" } ,
	{ "catclose" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "nl_catd" } , "int" } ,
	{ "creal" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "double" } ,
	{ "crealf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "float" } ,
	{ "creall" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "long double" } ,
	{ "cimag" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "double" } ,
	{ "cimagf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "float" } ,
	{ "cimagl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "long double" } ,
	{ "conj" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "conjf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "conjl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "carg" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "double" } ,
	{ "cargf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "float" } ,
	{ "cargl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "long double" } ,
	{ "cproj" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex double" } , "complex double" } ,
	{ "cprojf" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex float" } , "complex float" } ,
	{ "cprojl" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "complex long double" } , "complex long double" } ,
	{ "symlink" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "readlink" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char *","size_t" } , "ssize_t" } ,
	{ "canonicalize_file_name" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "realpath" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char *" } , "char *" } ,
	{ "calloc" , "libc.so.6" , 0 , 2 , NULL , NULL , { "size_t","size_t" } , "void *" } ,
	{ "btowc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "int" } , "wint_t" } ,
	{ "wctob" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "wint_t" } , "int" } ,
	{ "mbrtowc" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "wchar_t *","const char *","size_t","mbstate_t *" } , "size_t" } ,
	{ "mbrlen" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","size_t","mbstate_t *" } , "size_t" } ,
	{ "wcrtomb" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","wchar_t","mbstate_t *" } , "size_t" } ,
	{ "lfind" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const void *","const void *","size_t *","size_t","comparison_fn_t" } , "void *" } ,
	{ "lsearch" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const void *","void *","size_t *","size_t","comparison_fn_t" } , "void *" } ,
	{ "bsearch" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "const void *","const void *","size_t","size_t","comparison_fn_t" } , "void *" } ,
	{ "bind_textdomain_codeset" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "bind" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sockaddr *","socklen_t" } , "int" } ,
	{ "textdomain" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "bindtextdomain" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "char *" } ,
	{ "memcpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","const void *","size_t" } , "void *" } ,
	{ "wmemcpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "mempcpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","const void *","size_t" } , "void *" } ,
	{ "wmempcpy" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "memmove" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","const void *","size_t" } , "void *" } ,
	{ "wmemmove" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","size_t" } , "wchar_t *" } ,
	{ "memccpy" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "void *","const void *","int","size_t" } , "void *" } ,
	{ "memset" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void *","int","size_t" } , "void *" } ,
	{ "wmemset" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","wchar_t","size_t" } , "wchar_t *" } ,
	{ "strcpy" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","const char *" } , "char *" } ,
	{ "wcscpy" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "strdup" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "wcsdup" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const wchar_t *" } , "wchar_t *" } ,
	{ "stpcpy" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","const char *" } , "char *" } ,
	{ "wcpcpy" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "wchar_t *","const wchar_t *" } , "wchar_t *" } ,
	{ "bcopy" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const void *","void *","size_t" } , "void" } ,
	{ "bzero" , "libc.so.6" , 0 , 2 , pre_common_hook , NULL , { "void *","size_t" } , "void" } ,
	{ "memcmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","const void *","size_t" } , "int" } ,
	{ "wmemcmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *","size_t" } , "int" } ,
	{ "strcmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "wcscmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "int" } ,
	{ "strcasecmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "wcscasecmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *" } , "int" } ,
	{ "strncmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","size_t" } , "int" } ,
	{ "wcsncmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *","size_t" } , "int" } ,
	{ "strncasecmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","const char *","size_t" } , "int" } ,
	{ "wcsncasecmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","const wchar_t *","size_t" } , "int" } ,
	{ "strverscmp" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "int" } ,
	{ "bcmp" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const void *","const void *","size_t" } , "int" } ,
	{ "strtok" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char *","const char *" } , "char *" } ,
	{ "wcstok" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "wchar_t *","const wchar_t *","wchar_t **" } , "wchar_t *" } ,
	{ "strtok_r" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *","const char *","char **" } , "char *" } ,
	{ "strsep" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "char **","const char *" } , "char *" } ,
	{ "basename" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "char *" } ,
	{ "basename" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "dirname" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "char *" } , "char *" } ,
	{ "backtrace" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "void **","int" } , "int" } ,
	{ "backtrace_symbols" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "void *const *","int" } , "char **" } ,
	{ "backtrace_symbols_fd" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "void *const *","int","int" } , "void" } ,
	{ "strtol" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "long int" } ,
	{ "wcstol" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "long int" } ,
	{ "strtoul" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *retrict","char **","int" } , "unsigned long int" } ,
	{ "wcstoul" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "unsigned long int" } ,
	{ "strtoll" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "long long int" } ,
	{ "wcstoll" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "long long int" } ,
	{ "strtoq" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "long long int" } ,
	{ "wcstoq" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "long long int" } ,
	{ "strtoull" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "unsigned long long int" } ,
	{ "wcstoull" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "unsigned long long int" } ,
	{ "strtouq" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "unsigned long long int" } ,
	{ "wcstouq" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "unsigned long long int" } ,
	{ "strtoimax" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "intmax_t" } ,
	{ "wcstoimax" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "intmax_t" } ,
	{ "strtoumax" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","char **","int" } , "uintmax_t" } ,
	{ "wcstoumax" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const wchar_t *","wchar_t **","int" } , "uintmax_t" } ,
	{ "atol" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "long int" } ,
	{ "atoi" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "atoll" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "long long int" } ,
	{ "strtod" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char **" } , "double" } ,
	{ "strtof" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char **" } , "float" } ,
	{ "strtold" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","char **" } , "long double" } ,
	{ "wcstod" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","wchar_t **" } , "double" } ,
	{ "wcstof" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","wchar_t **" } , "float" } ,
	{ "wcstold" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const wchar_t *","wchar_t **" } , "long double" } ,
	{ "atof" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "double" } ,
	{ "atexit" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void (*) (void)" } , "int" } ,
	{ "on_exit" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "void (*)(int , void *)","void *" } , "int" } ,
	{ "asprintf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","const char *","..." } , "int" } ,
	{ "obstack_printf" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "struct obstack *","const char *","..." } , "int" } ,
	{ "asctime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct tm *" } , "char *" } ,
	{ "asctime_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct tm *","char *" } , "char *" } ,
	{ "ctime" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const time_t *" } , "char *" } ,
	{ "ctime_r" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const time_t *","char *" } , "char *" } ,
	{ "strftime" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char *","size_t","const char *","const struct tm *" } , "size_t" } ,
	{ "wcsftime" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "wchar_t *","size_t","const wchar_t *","const struct tm *" } , "size_t" } ,
	{ "argz_create" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char *const []","char **","size_t *" } , "error_t" } ,
	{ "argz_create_sep" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","int","char **","size_t *" } , "error_t" } ,
	{ "argz_count" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","size_t" } , "size_t" } ,
	{ "argz_extract" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const char *","size_t","char **" } , "void" } ,
	{ "argz_stringify" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "char *","size_t","int" } , "void" } ,
	{ "argz_add" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "char **","size_t *","const char *" } , "error_t" } ,
	{ "argz_add_sep" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char **","size_t *","const char *","int" } , "error_t" } ,
	{ "argz_append" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char **","size_t *","const char *","size_t" } , "error_t" } ,
	{ "argz_delete" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "char **","size_t *","char *" } , "void" } ,
	{ "argz_insert" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "char **","size_t *","char *","const char *" } , "error_t" } ,
	{ "argz_next" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","size_t","const char *" } , "char *" } ,
	{ "argz_replace" , "libc.so.6" , 0 , 5 , NULL , post_common_hook , { "char**","size_t*","constchar*","constchar*","unsigned*" } , "error_t" } ,
	{ "argp_parse" , "libc.so.6" , 0 , 6 , NULL , post_common_hook , { "const struct argp *","int","char **","unsigned","int *","void *" } , "error_t" } ,
	{ "argp_usage" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "const struct argp_state *" } , "void" } ,
	{ "argp_error" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const struct argp_state *","const char *","..." } , "void" } ,
	{ "argp_failure" , "libc.so.6" , 0 , 5 , pre_common_hook , NULL , { "const struct argp_state *","int","int","const char *","..." } , "void" } ,
	{ "argp_state_help" , "libc.so.6" , 0 , 3 , pre_common_hook , NULL , { "const struct argp_state *","FILE *","unsigned" } , "void" } ,
	{ "argp_help" , "libc.so.6" , 0 , 4 , pre_common_hook , NULL , { "const struct argp *","FILE *","unsigned","char *" } , "void" } ,
	{ "scandir" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","struct dirent ***","int (*) (const struct dirent *)","int (*) (const struct dirent **, const struct dirent **)" } , "int" } ,
	{ "alphasort" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct dirent **","const struct dirent **" } , "int" } ,
	{ "versionsort" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct dirent **","const struct dirent **" } , "int" } ,
	{ "scandir64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "const char *","struct dirent64 ***","int (*) (const struct dirent64 *)","int (*) (const struct dirent64 **, const struct dirent64 **)" } , "int" } ,
	{ "alphasort64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct dirent64 **","const struct dirent **" } , "int" } ,
	{ "versionsort64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct dirent64 **","const struct dirent64 **" } , "int" } ,
	{ "aligned_alloc" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "size_t","size_t" } , "void *" } ,
	{ "memalign" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "size_t","size_t" } , "void *" } ,
	{ "posix_memalign" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "void **","size_t","size_t" } , "int" } ,
	{ "valloc" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "size_t" } , "void *" } ,
	{ "alloca" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "size_t" } , "void *" } ,
	{ "setitimer" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","const struct itimerval *","struct itimerval *" } , "int" } ,
	{ "getitimer" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct itimerval *" } , "int" } ,
	{ "alarm" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "unsigned int" } , "unsigned int" } ,
	{ "aio_read" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb *" } , "int" } ,
	{ "aio_read64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb64 *" } , "int" } ,
	{ "aio_write" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb *" } , "int" } ,
	{ "aio_write64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb64 *" } , "int" } ,
	{ "lio_listio" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","struct aiocb *const []","int","struct sigevent *" } , "int" } ,
	{ "lio_listio64" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","struct aiocb64 *const []","int","struct sigevent *" } , "int" } ,
	{ "aio_init" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "const struct aioinit *" } , "void" } ,
	{ "aio_error" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct aiocb *" } , "int" } ,
	{ "aio_error64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const struct aiocb64 *" } , "int" } ,
	{ "aio_return" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb *" } , "ssize_t" } ,
	{ "aio_return64" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct aiocb64 *" } , "ssize_t" } ,
	{ "aio_fsync" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct aiocb *" } , "int" } ,
	{ "aio_fsync64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct aiocb64 *" } , "int" } ,
	{ "aio_suspend" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const struct aiocb *const []","int","const struct timespec *" } , "int" } ,
	{ "aio_suspend64" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const struct aiocb64 *const []","int","const struct timespec *" } , "int" } ,
	{ "aio_cancel" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct aiocb *" } , "int" } ,
	{ "aio_cancel64" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","struct aiocb64 *" } , "int" } ,
	{ "gettimeofday" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "struct timeval *","struct timezone *" } , "int" } ,
	{ "settimeofday" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct timeval *","const struct timezone *" } , "int" } ,
	{ "adjtime" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct timeval *","struct timeval *" } , "int" } ,
	{ "adjtimex" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "struct timex *" } , "int" } ,
	{ "addseverity" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "int","const char *" } , "int" } ,
	{ "setmntent" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const char *","const char *" } , "FILE *" } ,
	{ "endmntent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "int" } ,
	{ "getmntent" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "FILE *" } , "struct mntent *" } ,
	{ "getmntent_r" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "FILE *","struct mntent *","char *","int" } , "struct mntent *" } ,
	{ "addmntent" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "FILE *","const struct mntent *" } , "int" } ,
	{ "hasmntopt" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "const struct mntent *","const char *" } , "char *" } ,
	{ "semctl" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","int","int" } , "int" } ,
	{ "semget" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "key_t","int","int" } , "int" } ,
	{ "semop" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "int","struct sembuf *","size_t" } , "int" } ,
	{ "semtimedop" , "libc.so.6" , 0 , 4 , NULL , post_common_hook , { "int","struct sembuf *","size_t","const struct timespec *" } , "int" } ,
	{ "sem_init" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "sem_t *","int","unsigned int" } , "int" } ,
	{ "sem_destroy" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sem_t *" } , "int" } ,
	{ "*sem_open" , "libc.so.6" , 0 , 3 , NULL , post_common_hook , { "const char *","int","..." } , "sem_t" } ,
	{ "sem_close" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sem_t *" } , "int" } ,
	{ "sem_unlink" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "const char *" } , "int" } ,
	{ "sem_wait" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sem_t *" } , "int" } ,
	{ "sem_timedwait" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "sem_t *","const struct timespec *" } , "int" } ,
	{ "sem_trywait" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sem_t *" } , "int" } ,
	{ "sem_post" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "sem_t *" } , "int" } ,
	{ "sem_getvalue" , "libc.so.6" , 0 , 2 , NULL , post_common_hook , { "sem_t *","int *" } , "int" } ,
	{ "brk" , "libc.so.6" , 0 , 1 , NULL , post_common_hook , { "void *" } , "int" } ,
	{ "*sbrk" , "libc.so.6" , 0 , 1 , pre_common_hook , NULL , { "ptrdiff_t" } , "void" }
	*/
		//	{"malloc", "libc.so.6", 0, 1, NULL, post_malloc_hook, {"size_t"}, "void *"},
		// calloc, libc 
		//	{"calloc", "libc.so.6", 0, 2, NULL, NULL, {"size_t","size_t"}, "void *"},
		// realloc, libc 
		//	{"realloc", "libc.so.6", 0, 2, NULL, NULL, {"void *","size_t"}, "void *"},
		// free, libc 
		//	{"free", "libc.so.6", 0, 1, pre_free_hook, NULL, {"void *"}, "void"},
		// strcpy, libc 
	{"strcpy", "libc.so.6", 0, 2, NULL, post_strcpy_hook, {"char *", "char *"}, "char *"}, 
		// strncpy, libc 
	{"strncpy", "libc.so.6", 0, 3, NULL, post_strncpy_hook, {"char *","char *","size_t"}, "char *"},
	{ "strtok" , "libc.so.6" , 0 , 2 , NULL , post_strtok_hook , { "char *","const char *" } , "char *" },
	{ "strtok_r" , "libc.so.6" , 0 , 3 , NULL , post_strtok_r_hook , { "char *","const char *","char **" } , "char *" },
	{ "rawmemchr" , "libc.so.6" , 0 , 2 , pre_rawmemchr_hook , NULL , { "const void *","int" } , "void *" },
	{ "memchr" , "libc.so.6" , 0 , 3 , pre_memchr_hook , NULL , { "const void *","int","size_t" } , "void *" } ,
	{ "memrchr" , "libc.so.6" , 0 , 3 , pre_memchr_hook , NULL , { "const void *","int","size_t" } , "void *" } ,
	{ "strlen" , "libc.so.6" , 0 , 1 , NULL , post_strlen_hook , { "const char *" } , "size_t" } ,
	{ "strncmp" , "libc.so.6" , 0 , 3 , NULL , post_strncmp_hook , { "const char *","const char *","size_t" } , "int" },
	{ "strndup" , "libc.so.6" , 0 , 2 , NULL , post_strndup_hook , { "const char *","size_t" } , "char *" } ,
	{ "strdup" , "libc.so.6" , 0 , 1 , NULL , post_strdup_hook , { "const char *" } , "char *" } ,
	{ "strnlen" , "libc.so.6" , 0 , 2 , NULL , post_strnlen_hook , { "const char *","size_t" } , "size_t" } ,
	{ "strcmp" , "libc.so.6" , 0 , 2 , NULL , post_strcmp_hook , { "const char *","const char *" } , "int" } ,
	{ "memset" , "libc.so.6" , 0 , 3 , NULL , post_memset_hook , { "void *","int","size_t" } , "void *" } ,
	{ "memmove" , "libc.so.6" , 0 , 3 , NULL , post_memmove_hook , { "void *","const void *","size_t" } , "void *" } ,
	{ "memcpy" , "libc.so.6" , 0 , 3 , NULL , post_memcpy_hook , { "void *","const void *","size_t" } , "void *" } ,
	{ "memcmp" , "libc.so.6" , 0 , 3 , NULL , post_memcmp_hook , { "const void *","const void *","size_t" } , "int" },
	{"malloc", "libc.so.6", 0, 1, NULL, post_malloc_hook, {"size_t"}, "void *"}
};

/* heap manage */
//extern PIN_MUTEX HeapLock;
//extern heap_desc_map_t heap_desc_map;
//extern heap_ctx_map_t heap_ctx_map;

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

	for(int i=0;i<8;i++){
		threads_ctx[tid].libcall_ctx.arg_taint[0][i] = threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDI][i];
		threads_ctx[tid].libcall_ctx.arg_taint[1][i] = threads_ctx[tid].vcpu.gpr_file[DFT_REG_RSI][i];
		threads_ctx[tid].libcall_ctx.arg_taint[2][i] = threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDX][i];
		threads_ctx[tid].libcall_ctx.arg_taint[3][i] = threads_ctx[tid].vcpu.gpr_file[DFT_REG_RCX][i];
		threads_ctx[tid].libcall_ctx.arg_taint[4][i] = threads_ctx[tid].vcpu.gpr_file[DFT_REG_R8][i];
	}
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
			//			if((strcmp(libcall_desc[i].name, "malloc") == 0 || strcmp(libcall_desc[i].name,"free") == 0 ) || flag == 1){
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
			//			}
		}
	}
}


VOID libcall_trace_inspect(TRACE trace, VOID *v)
{
}
/*
   static void pre_common_hook(libcall_ctx_t* ctx){
   if(ctx->arg == NULL){
   return;
   }
   LOG("pre " + decstr(flag) + " " + std::string(libcall_desc[ctx->nr].name) + "\n");
//        LOG(decstr(libcall_desc[ctx->nr].nargs) + " "  + std::string(libcall_desc[ctx->nr].name) + "\n");
for(int i=0;i<libcall_desc[ctx->nr].nargs;i++){
if(type_map.find(libcall_desc[ctx->nr].args_type[i]) == type_map.end()){
continue;
}
switch(type_map[libcall_desc[ctx->nr].args_type[i]]){
case 0:
{
tag_t t = file_tagmap_getb(ctx->arg[i]);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t)limit_offset)
LOG(std::string(libcall_desc[ctx->nr].name) + " " + decstr(i) + " " + tag_sprint(t) + "\n");
break;
}
case 1:
{
ADDRINT s = (ADDRINT)  &ctx->arg[i];
tag_t t = file_tagmap_getb(s);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t)limit_offset)
LOG(std::string(libcall_desc[ctx->nr].name) + " " + decstr(i) + " " + tag_sprint(t) + "\n");
break;
}
}
}
}

static void post_common_hook(libcall_ctx_t* ctx){
if(ctx->arg == NULL){
return;
}	
//	LOG(decstr(libcall_desc[ctx->nr].nargs) + " "  + std::string(libcall_desc[ctx->nr].name) + "\n");
LOG("pre " + decstr(flag) + " " + std::string(libcall_desc[ctx->nr].name) + "\n");
for(int i=0;i<libcall_desc[ctx->nr].nargs;i++){
if(type_map.find(libcall_desc[ctx->nr].args_type[i]) == type_map.end()){
continue;
}
switch(type_map[libcall_desc[ctx->nr].args_type[i]]){
case 0:
{
tag_t t = file_tagmap_getb(ctx->arg[i]);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t)limit_offset)
LOG(std::string(libcall_desc[ctx->nr].name) + " " + decstr(i) + " " + tag_sprint(t) + "\n");
break;
}
case 1:
{
ADDRINT s = (ADDRINT)  &ctx->arg[i];
tag_t t = file_tagmap_getb(s);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t)limit_offset)
LOG(std::string(libcall_desc[ctx->nr].name) + " " + decstr(i) + " " + tag_sprint(t) + "\n");
break;
}
}
}
if(type_map.find(libcall_desc[ctx->nr].ret_type) != type_map.end()){
switch(type_map[libcall_desc[ctx->nr].ret_type]){
case 0:
{
tag_t t = file_tagmap_getb(ctx->ret);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset)
LOG(std::string(libcall_desc[ctx->nr].name) + " ret "  + tag_sprint(t) + "\n");
break;
}
case 1:
{
ADDRINT s = (ADDRINT)  &ctx->ret;
tag_t t = file_tagmap_getb(s);
if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset)
	LOG(std::string(libcall_desc[ctx->nr].name) + " ret "  + tag_sprint(t) + "\n");
	break;
	}
default:{
		break;
	}
}
}

}*/


static void post_strlen_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->ret;
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;  
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strlen char* " << *it << " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strlen char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
	}
}
static void post_malloc_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		std::string s="";
		bool fl = 0;
		for(int i=0;i<8;i++){
			tag_t t1 = ctx->arg_taint[0][i];
			if(t1.numberOfOnes() > 0 && t1.numberOfOnes() <= 2){
				fl = 1;
				s += tag_sprint(t1);
				s += ":";
			}
		}
		if(fl == 1){
			reward_taint << "malloc int " << s << std::endl;
			reward_taint << flush;
		}
	}
}

static void post_strnlen_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->ret;
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it; 
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));

				reward_taint << "strnlen char* " << *it << " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strnlen char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}  
		}
	}
}

static void post_strdup_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) strlen((char *)addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it; 
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));

				reward_taint << "strdup char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strdup char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}  
		}
	}
}

static void post_strndup_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) strlen((char *)addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it; 
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));

				reward_taint << "strndup char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strndup char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
		int n = (ADDRINT) ctx->arg[1];
		ADDRINT addr2 = (ADDRINT) &n;
		if(addr2){
			tag_t t = file_tagmap_getb(addr2);
			if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset){
				tag_t::const_iterator it = t.begin();
				reward_taint << "strndup int " << *it << std::endl;
				reward_taint << flush; 
				//LOG("strndup int " + tag_sprint(t) + "\n");
			}
		}
	}
}

static void post_memset_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->arg[2];
			bool fl = 0;
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));

				reward_taint << "memset char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("memset char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
                std::string s="";
                bool fl = 0;
                for(int i=0;i<8;i++){
                        tag_t t1 = ctx->arg_taint[2][i];
                        if(t1.numberOfOnes() > 0 && t1.numberOfOnes() <= 2){
                                fl = 1;
                                s += tag_sprint(t1);
                                s += ":";
                        }
                }
                if(fl == 1){
                        reward_taint << "memset int " << s << std::endl;
                        reward_taint << flush;
                }

	}
}

static void post_memmove_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret ){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;  
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "memmove char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("memmove char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
                std::string s="";
                bool fl = 0;
                for(int i=0;i<8;i++){
                        tag_t t1 = ctx->arg_taint[2][i];
                        if(t1.numberOfOnes() > 0 && t1.numberOfOnes() <= 2){
                                fl = 1;
                                s += tag_sprint(t1);
                                s += ":";
                        }
                }
                if(fl == 1){
                        reward_taint << "memmove int " << s << std::endl;
                        reward_taint << flush;
                }

	}

}

static void post_memcpy_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret ){
		ADDRINT addr1 = (ADDRINT) ctx->arg[1];
		if(addr1){
			int nr = (int) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;  
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "memcpy char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("memcpy char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
                std::string s="";
                bool fl = 0;
                for(int i=0;i<8;i++){
                        tag_t t1 = ctx->arg_taint[2][i];
                        if(t1.numberOfOnes() > 0 && t1.numberOfOnes() <= 2){
                                fl = 1;
                                s += tag_sprint(t1);
                                s += ":";
                        }
                }
                if(fl == 1){
                        reward_taint << "memcpy int " << s << std::endl;
                        reward_taint << flush;
                }

	}
}

static void post_memcmp_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->ret ){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		ADDRINT addr2 = (ADDRINT) ctx->arg[1];
		if(addr1 && addr2){
			int nr = (int) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1);
			std::string result;
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				try{
					unsigned char c = *((unsigned char *)(addr1+i));
					result.push_back(lut[c>>4]);
					result.push_back(lut[c&15]);
				}catch(exception &e){
					fl=0;
					break;
				}

				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;  
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "memcmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("memcmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
		if(addr2 && addr1){
			int nr = (int) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr2);
			std::string result;
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr2 + i);
				int prev = -1;
				int cur;
				try{
					unsigned char c = *((unsigned char *)(addr1+i));
					result.push_back(lut[c>>4]);
					result.push_back(lut[c&15]);
				}catch(exception &e){
					fl=0;
					break;
				}
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "memcmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("memcmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
                std::string s="";
                bool fl = 0;
                for(int i=0;i<8;i++){
                        tag_t t1 = ctx->arg_taint[2][i];
                        if(t1.numberOfOnes() > 0 && t1.numberOfOnes() <= 2){
                                fl = 1;
                                s += tag_sprint(t1);
                                s += ":";
                        }
                }
                if(fl == 1){
                        reward_taint << "memcmp int " << s << std::endl;
                        reward_taint << flush;
                }

	}
}




static void post_strcmp_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		ADDRINT addr2 = (ADDRINT) ctx->arg[1];
		if(addr1 && addr2){
			uint32_t nr = (uint32_t)strlen((char *)addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			std::string s((char *)addr2);
			std::string result;
			nr = min((uint32_t)nr, (uint32_t)s.length());
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				unsigned char c = (unsigned char)s[i];
				result.push_back(lut[c>>4]);
				result.push_back(lut[c&15]);
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strcmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("strcmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}

			/*                        if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset)
						  LOG("strcmp char * " + tag_sprint(t) + " " + decstr(nr) + " " + std::string((char *)addr) + " " + std::string((char *)ctx->arg[1]) + "\n");*/
		}
		if(addr2 && addr1){
			uint32_t nr = (uint32_t)strlen((char *)addr2);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr2 );
			std::string s((char *)addr1);
			std::string result;
			nr = min((uint32_t)nr, (uint32_t)s.length());
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr2 + i);
				int prev = -1;
				int cur;
				unsigned char c = (unsigned char) s[i];
				result.push_back(lut[c>>4]);
				result.push_back(lut[c&15]);
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//		if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strcmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("strcmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//		}
			}
		}
	}
}

static void post_strncmp_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		ADDRINT addr2 = (ADDRINT) ctx->arg[1];
		if(addr1 && addr2){
			uint32_t nr = (uint32_t) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			std::string s((char *)addr2);
			std::string result;
			nr = min((uint32_t)nr, (uint32_t)s.length());
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				unsigned char c = (unsigned char) s[i];
				result.push_back(lut[c>>4]);
				result.push_back(lut[c&15]);
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strncmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("strncmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}

		}
		if(addr2 && addr1){
			uint32_t nr = (uint32_t) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr2 );
			std::string s((char *)addr1);
			std::string result;
			nr = min((uint32_t)nr, (uint32_t)s.length());
			result.reserve(2*nr);
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr2 + i);
				int prev = -1;
				int cur;
				unsigned char c = (unsigned char) s[i];
				result.push_back(lut[c>>4]);
				result.push_back(lut[c&15]);
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strncmp char* " << *it <<  " " << nr << " " << result << std::endl;
				reward_taint << flush; 
				//LOG("strncmp char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}

		}
	}
}



static void post_strcpy_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->arg[0] == ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = strlen((char *)addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strcpy char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strcpy char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
	}
}

static void post_strncpy_hook(libcall_ctx_t* ctx){
	if(ctx->arg && ctx->arg[0] == ctx->ret){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->arg[2];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strncpy char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strncpy char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
	}
}

/*static void pre_strncmp_hook(libcall_ctx_t* ctx){
  if(ctx->arg ){
  ADDRINT addr = (ADDRINT) ctx->arg[0];
  if(addr){
  int nr = (int) ctx->arg[2];
  tag_t t = file_tagmap_getb(addr);
  if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset)
  LOG("strncmp char * " + tag_sprint(t) + " " + decstr(nr) + "\n");
  }
  ADDRINT addr2 = (ADDRINT) ctx->arg[1];
  if(addr2){
  tag_t t = file_tagmap_getb(addr2);
  int nr = (int) ctx->arg[2];
  if(t.numberOfOnes() > 0 && t.numberOfOnes() <= (uint32_t) limit_offset)
  LOG("strncmp char * " + tag_sprint(t) + " " + decstr(nr) + "\n");
  }
  }
  }*/

static void post_strtok_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = strlen((char *) addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//	if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strtok char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strtok char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//	}
			}
		}
		ADDRINT addr2 = (ADDRINT) ctx->arg[1];
		if(addr2){
			int nr = strlen((char *) addr2);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr2 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr2 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strtok char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strtok char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}

		}
	}
}

static void post_strtok_r_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = strlen((char *) addr1);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				// if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strtok_r char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strtok_r char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
		ADDRINT addr2 = (ADDRINT) ctx->arg[1];
		if(addr2){
			int nr = strlen((char *) addr2);
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr2 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr2 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				// if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "strtok_r char* " << *it <<  " " << nr << std::endl;
				reward_taint << flush; 
				//LOG("strtok_r char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}

		}
	}
}


static void pre_rawmemchr_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = strlen((char *) addr1);
			unsigned char c = (unsigned char) ctx->arg[1];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				//reward_taint << "rawmemchr char* " << *it <<  " " << nr << " " << hex(c) << std::endl;
				reward_taint << "rawmemchr char* " << *it <<  " " << nr  << " " << int(c) << std::endl;
				reward_taint << flush; 
				//LOG("rawmemchr char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//              }
			}
		}
		char c = (char) ctx->arg[1];
		ADDRINT addr2 = (ADDRINT) &c;
		if(addr2){
			tag_t t2 = file_tagmap_getb(addr2);
			if(t2.numberOfOnes() > 0 && t2.numberOfOnes() <= (uint32_t) limit_offset){
				tag_t::const_iterator it = t2.begin();
				reward_taint << "rawmemchr char " << *it  << std::endl;
				reward_taint << flush; 
				//LOG("rawmemchr char " + tag_sprint(t2) + "\n");
			}
		}
	}
}

static void pre_memchr_hook(libcall_ctx_t* ctx){
	if(ctx->arg){
		ADDRINT addr1 = (ADDRINT) ctx->arg[0];
		if(addr1){
			int nr = (int) ctx->arg[2];
			unsigned char c = (unsigned char) ctx->arg[1];
			bool fl = 0; 
			tag_t  t1 = file_tagmap_getb(addr1 );
			for(uint32_t i=0;i<(uint32_t) nr;i++){
				tag_t  t = file_tagmap_getb(addr1 + i);
				int prev = -1;
				int cur;
				if(t.numberOfOnes() == 1){
					tag_t::const_iterator it = t.begin();
					cur = *it;   
					if((prev == -1) || (prev != -1 && cur == prev+1)){
						prev = cur;
						fl = 1;
						continue;
					}else{
						fl = 0;
						break;
					}
				}else{
					fl = 0;
					break;
				}
			}
			if(fl == 1){
				tag_t::const_iterator it = t1.begin();
				//if(stored.find(std::make_pair(*it, nr)) == stored.end()){
				stored.insert(std::make_pair(*it, nr));
				reward_taint << "memchr char* " << *it <<  " " << nr << " " << int(c)  << std::endl;
				reward_taint << flush;
				//LOG("memchr char* " + tag_sprint(t1) + " " + decstr(nr) + "\n");
				//}
			}
		}
		char c = (char) ctx->arg[1];
		ADDRINT addr2 = (ADDRINT) &c;
		if(addr2){
			tag_t t2 = file_tagmap_getb(addr2);
			if(t2.numberOfOnes() > 0 && t2.numberOfOnes() <= (uint32_t) limit_offset){
				tag_t::const_iterator it = t2.begin();
				reward_taint << "memchr char " << *it << std::endl;
				reward_taint << flush;
				//LOG("memchr char " + tag_sprint(t2) + "\n");
			}
		}
		int n = (int) ctx->arg[2];
		ADDRINT addr3 = (ADDRINT) &n;
		if(addr3){
			tag_t t3 = file_tagmap_getb(addr3);
			if(t3.numberOfOnes() > 0 && t3.numberOfOnes() <= (uint32_t) limit_offset){
				tag_t::const_iterator it = t3.begin();
				reward_taint << "memchr int " << *it << std::endl;
				reward_taint << flush;
				//LOG("memchr int " + tag_sprint(t3) + "\n");
			}
		}
	}
}

