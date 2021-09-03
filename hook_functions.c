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
  int cpt = 0;
  while(s_trustlet) {
    void (*f_pointer)(void) = NULL;
    if (need_hook(s_trustlet->name, &f_pointer)) {
      cpt++;
      if (s_trustlet->got_addr != NULL) {
        // Hook function by replacing its address in the GOT : simple
        *(Elf_Addr *)(s_trustlet->got_addr) = (Elf_Addr)(f_pointer);
        s_trustlet->real_addr = f_pointer;
      } else {
        // Hook function by patching it (redirect to our hook at the begining of it) : less simple
        // We'll replace the start of the hooked function by the following assembly code : 
        //
        // movw ip, #0x5678
        // movt ip, #0x1234
        // bx ip
        //
        // Where 0x12345678 is the address of our function.

        if (((Elf_Addr)s_trustlet->real_addr) % 2 == 1) {
          // Thumb mode
          char *real_func = ((Elf_Addr)s_trustlet->real_addr) & 0xfffffffe;
          real_func[0] = 0x40 + (((Elf_Addr)(f_pointer) >> (4*3)) & 0x0000000f);
          real_func[1] = (((Elf_Addr)(f_pointer) >> (4*2)) & 0x0000000f) < 8 ? 0xF2 : 0xF6;
          real_func[2] = ((Elf_Addr)(f_pointer)) & 0x000000ff;
          real_func[3] = (((((Elf_Addr)(f_pointer) >> (4*2)) & 0x0000000f) % 8) << 4) + 0x0C;

          real_func[4] = 0xC0 + (((Elf_Addr)(f_pointer) >> (4*7)) & 0x0000000f);
          real_func[5] = (((Elf_Addr)(f_pointer) >> (4*6)) & 0x0000000f) < 8 ? 0xF2 : 0xF6;
          real_func[6] = (((Elf_Addr)(f_pointer)) >> 4*4) & 0x000000ff;
          real_func[7] = (((((Elf_Addr)(f_pointer) >> (4*6)) & 0x0000000f) % 8) << 4) + 0x0C;


          real_func[8] = 0x60;
          real_func[9] = 0x47;
        } else {
          // ARM mode
          char *real_func = ((Elf_Addr)s_trustlet->real_addr);

          real_func[0] = ((Elf_Addr)(f_pointer)) & 0x000000ff;
          real_func[1] = 0xC0 + (((Elf_Addr)(f_pointer) >> (4*2)) & 0x0000000f);
          real_func[2] = (((Elf_Addr)(f_pointer) >> (4*3)) & 0x0000000f);
          real_func[3] = 0xE3;

          real_func[4] = (((Elf_Addr)(f_pointer)) >> 4*4) & 0x000000ff;
          real_func[5] = 0xC0 + (((Elf_Addr)(f_pointer) >> (4*6)) & 0x0000000f);
          real_func[6] = 0x40 + (((Elf_Addr)(f_pointer) >> (4*7)) & 0x0000000f);
          real_func[7] = 0xE3;

          real_func[8] = 0x3C;
          real_func[9] = 0xFF;
          real_func[10] = 0x2F;
          real_func[11] = 0xE1;
        }
      }
    }
    s_trustlet = s_trustlet->next;
  }
  log_message(INFO_MSG, "Done. Successfully hooked %d function(s).\n", cpt);
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
