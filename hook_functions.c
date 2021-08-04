#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "elf_helper.h"
#include "loader.h"

bool need_hook(char *name) {
    return true;
}
void hook_functions(struct Symbol *s_cmnlib) {
  while(s_cmnlib) {
    if (need_hook(s_cmnlib->name)) {
      // TODO
    }
    s_cmnlib = s_cmnlib->next;
  }
}

int qsee_log(int msg_level, const char *msg, ...) {
    int ret;

    /* Declare a va_list type variable */
    va_list myargs;

    /* Initialise the va_list variable with the ... after fmt */

    va_start(myargs, msg);

    /* Forward the '...' to vprintf */
    ret = vprintf(msg, myargs);
    printf("\n");

    /* Clean up the va_list */
    va_end(myargs);
 
    fflush(stdout);
    
    return ret;
}
