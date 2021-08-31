#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "hook_functions.h"
#include "elf_helper.h"

const f_tuple hooked_functions[] = {
    {"qsee_log", qsee_log}
};

bool need_hook(char *name, void (**f_pointer)(void)) {
  for (int i = 0; i < (sizeof(hooked_functions)/sizeof(f_tuple)); i++) {
    if (strcmp(name, (hooked_functions + i)->f_name) == 0) {
      *f_pointer = (hooked_functions + i)->f_pointer;
      return true;
    }
  }  
  return false;
}
void hook_functions(struct Symbol *s_trustlet) {
  while(s_trustlet) {
    void (*f_pointer)(void) = NULL;
    if (need_hook(s_trustlet->name, &f_pointer)) {
      printf("Hooked function %s\n", s_trustlet->name);
      s_trustlet->real_addr = f_pointer;
      if (s_trustlet->got_addr != NULL)
        *(Elf_Addr *)(s_trustlet->got_addr) = (Elf_Addr)(f_pointer);
    }
    s_trustlet = s_trustlet->next;
  }
}

int qsee_log(int msg_level, const char *msg, ...) {
    int ret;
    va_list myargs;
    va_start(myargs, msg);
    ret = vprintf(msg, myargs);
    va_end(myargs);
    printf("\n");
    fflush(stdout);
    return ret;
}
