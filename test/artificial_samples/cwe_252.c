#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>

/*
Explanation of the general naming scheme used for functions in this test and how
to parse the comments.

Everything between two horizontal / *---- ... ---* / lines belongs to a single
test case. If there are no `CWE_WARNING...` comments, then the test should not
cause a warning. If there are such comments, then the test case should cause
exactly one warning, where the first reported address (source) belongs to the
line with the comment that has a `1` and the second reported address (sink)
belongs to a line with a `2`. The `reason=` field in the comment should match
the one in the cwe warning.

Now to the names:

cwe252_ INTER_OR_INTRA STORAGE+ RETURN? USAGE

INTER_OR_INTRA -> intra | inter_caller | inter_callee
Tells you if the test is exercising our interprocedural or intraprocedural
analysis, and if the function is the caller or callee for interprocedural tests.

STORAGE -> r | s | h | g
Tells you where the relevant tainted values will be stored (register, stack,
heap, global). So the test checks that we properly track those locations.

RETURN -> return | return ptr | return param | gptr
For interprocedural test cases, this tells you how the information is propagated
from the callee to the caller. Taint may be returned directly, a pointer to
taint may be returned, taint may be written to a pointer parameter, taint may be
written to a pointer that is stored in a global variable.

USAGE -> lost | unchecked | checked
This tells you what the test does with the tainted value. Is there a point where
all taint vanishes from the state (lost)? Is the taint reaching the end of a
function without being returned (unchecked)? Or is there a check on every path
from the call site to the end of the function (checked)?
*/

char *g_ret;
char **g_ret_store;

int main()
{
    return 1;
}

int some_func(int x)
{
    int seed = x + (int)time(NULL);
    srand(seed);
    return seed;
}

/*----------------------------------------------------------------------------*/

static void cwe252_inter_callee_g_checked(char *buf, size_t n)
{
    g_ret = fgets(buf, n, stdin);
}

int cwe252_inter_caller_g_checked(void)
{
    int number = rand();
    char buf[10];
    size_t n = sizeof(buf);

    cwe252_inter_callee_g_checked(buf, n);

    if (g_ret)
        printf("%s", buf);

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

static void cwe252_inter_callee_g_unchecked(void)
{
    char buf[10];

    g_ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    printf("%p: %s\n", buf, buf);
}

int cwe252_inter_caller_g_unchecked(void)
{
    int number = rand();

    cwe252_inter_callee_g_unchecked();

    printf("My number was %d\n", number);

    return number *
           number; // CWE_WARNING, 2, reason=isolated_returns_no_reg_taint
}

/*----------------------------------------------------------------------------*/

static void cwe252_inter_callee_h_gptr_checked(char *buf, size_t n)
{
    g_ret_store = malloc(8);

    if (!g_ret_store)
        exit(1);

    *g_ret_store = fgets(buf, n, stdin);
}

int cwe252_inter_caller_h_gptr_checked(void)
{
    int number = rand();
    char buf[10];
    size_t n = sizeof(buf);

    cwe252_inter_callee_h_gptr_checked(buf, n);

    if (*g_ret_store)
        printf("%s", buf);

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

static char **cwe252_inter_callee_h_return_ptr_checked(char *buf, size_t n)
{
    char **ret_store = malloc(8);

    if (!ret_store)
        return NULL;

    *ret_store = fgets(buf, n, stdin);

    return ret_store;
}

int cwe252_inter_caller_h_return_ptr_checked(void)
{
    int number = rand();
    char buf[10];
    size_t n = sizeof(buf);
    char **ret_store = cwe252_inter_callee_h_return_ptr_checked(buf, n);

    if (!ret_store)
        exit(1);

    if (*ret_store)
        printf("%s", buf);

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

static char *cwe252_inter_callee_r_return_lost(void)
{
    char buf[10];

    return fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1
}

int cwe252_inter_caller_r_return_lost(void)
{
    int number = rand();

    cwe252_inter_callee_r_return_lost();

    printf("My number was %d\n", number); // CWE_WARNING, 2, reason=empty_state

    return number * number;
}

/*----------------------------------------------------------------------------*/

static char *cwe252_inter_callee_rh_return_checked(void)
{
    char buf[10];
    char *volatile *ret_storage = malloc(8);

    if (!ret_storage) {
        return NULL;
    }

    *ret_storage = fgets(buf, sizeof(buf), stdin);

    return *ret_storage;
}

int cwe252_inter_caller_rh_return_checked(void)
{
    int number = rand();
    char *ret;

    ret = cwe252_inter_callee_rh_return_checked();

    if (!ret) {
        abort();
    }

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

static void cwe252_inter_callee_s_return_param_checked(char **ret_store,
                                                       char *buf, size_t n)
{
    *ret_store = fgets(buf, n, stdin);
}

int cwe252_inter_caller_s_return_param_checked(void)
{
    int number = rand();
    char buf[10];
    size_t n = sizeof(buf);
    char *ret;

    cwe252_inter_callee_s_return_param_checked(&ret, buf, n);

    if (ret)
        printf("%s", buf);

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

static void cwe252_inter_callee_s_unchecked(void)
{
    char buf[10];
    char *volatile ret;

    ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    printf("%p: %s\n", buf, buf); // CWE_WARNING, 2, reason=return_no_taint
}

int cwe252_inter_caller_s_unchecked(void)
{
    int number = rand();

    cwe252_inter_callee_s_unchecked();

    printf("My number was %d\n", number);

    return number * number;
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_g_lost(void)
{
    char buf[10];
    static char *volatile ret;

    ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    if (rand() == 0) {
        ret = buf; // CWE_WARNING, 2, reason=empty_state
    }

    if (ret) {
        puts(buf);
    }
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_g_unchecked(void)
{
    char buf[10];
    static char *volatile ret;

    ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    printf("%p: %s\n", buf,
           buf); // CWE_WARNING, 2, reason=isolated_returns_no_reg_taint
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_h_lost(void)
{
    char buf[10];
    char *volatile *ret = malloc(8);

    if (!ret) {
        return;
    }

    *ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    if (rand() == 0) {
        *ret = buf; // CWE_WARNING, 2, reason=empty_state
    }

    if (*ret) {
        puts(buf);
    }
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_r_checked(void)
{
    char buf[10];
    char *ret;

    ret = fgets(buf, sizeof(buf), stdin);

    if (ret) {
        puts(buf);
    }
}

/*----------------------------------------------------------------------------*/

extern int some_func(int);

void cwe252_intra_r_lost(void)
{
    char buf[10];

    fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    some_func(42); // CWE_WARNING, 2, reason=empty_state

    puts(buf);
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_s_lost(void)
{
    char buf[10];
    char *volatile ret;

    ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1

    if (rand() == 0) {
        ret = buf; // CWE_WARNING, 2, reason=empty_state
    }

    if (ret) {
        puts(buf);
    }
}

/*----------------------------------------------------------------------------*/

void cwe252_intra_s_unchecked(void)
{
    char buf[10];
    char *volatile ret;

    ret = fgets(buf, sizeof(buf), stdin); // CWE_WARNING, 1
    some_func(42); // CWE_MODULE, 2, reason=isolated_returns_no_reg_taint
}

/*----------------------------------------------------------------------------*/
