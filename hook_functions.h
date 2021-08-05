#ifndef _HOOK_FUNCTIONS_H
#define	_HOOK_FUNCTIONS_H 1

#include "loader.h"

typedef struct {
    const char *f_name;
    void (*f_pointer)(void);
} f_tuple;

void hook_functions(struct Symbol *s_cmnlib);
bool need_hook(char *name, void (**f_pointer)(void));

int qsee_log(int msg_level, const char *msg, ...);

#endif /* hook_functions.h */