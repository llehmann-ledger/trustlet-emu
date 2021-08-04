#ifndef _HOOK_FUNCTIONS_H
#define	_HOOK_FUNCTIONS_H 1

bool need_hook(char *name);
void hook_functions(struct Symbol *s_cmnlib);

int qsee_log(int msg_level, const char *msg, ...);

#endif /* hook_functions.h */