#ifndef _HOOK_FUNCTIONS_H
#define	_HOOK_FUNCTIONS_H 1

#include "loader.h"

typedef struct {
    const char *f_name;
    void (*f_pointer)(void);
} f_tuple;

void hook_functions(struct Symbol *s_trustlet);
bool need_hook(char *name, void (**f_pointer)(void));

int qsee_log(int msg_level, const char *msg, ...)  __attribute__ ((target ("thumb")));

#endif /* hook_functions.h */