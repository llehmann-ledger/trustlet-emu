#include "loader.h"
#include "elf_helper.h"
#include <stdbool.h>

int map_trustlet(struct Trustlet *t_let) {

  struct Segment *dyn_seg = t_let->segments;
  bool stop = false;
  // Find dynamic segment
  while (dyn_seg && !stop) {
    if (dyn_seg->type == PT_DYNAMIC) {
      stop = true;
    } else {
      dyn_seg = dyn_seg->next;
    }
  }
  
  if (!dyn_seg) {
    printf("No dynamic segment. Stopping.\n");
    exit -1;
  }

  size_t base_addr = BASE_ADDR_TRUSTLET;

  printf("\nDEBUG: dynamic parsing step:\n\n");
  struct Dyn_parser_helper *res = parse_dynamic(dyn_seg->mem, base_addr);
  
  printf("\nDEBUG: symbols parsing step:\n\n");
  struct Symbol *sym_list = parse_symbols(res->dt_symtab, res->dt_strtab, base_addr);
  
  printf("\nDEBUG: parsing DT_REL step:\n\n");
  parse_rel(sym_list, res->dt_rel, base_addr);
  
  printf("\nDEBUG: parsing DT_JMPREL step:\n\n");
  parse_jmprel(sym_list, res->dt_jmprel, base_addr);

  printf("\n~ THAT'S ALL FOLKS ~\n");

}

/*
** TODO
*/
int map_cmnlib(const char* name) {

}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("usage: trustlet_path\n");
    return 0;
  }
  // TODO : Get name from argv
  struct Trustlet *t_let = parse_elf(argv[1]);
  // TODO : Get name fromconst char* name, void* t_code, void* t_data argv
  map_trustlet(t_let);

  // TODO : map_cmnlib

  // Seek to entry point
  struct Segment *code_seg = t_let->segments;
  bool stop = false;
  // Find dynamic segment
  int i = 0;
  while (code_seg && !stop) {
    if (code_seg->type == PT_LOAD && (code_seg->perm & (PF_X))) {
      stop = true;
    } else {
      code_seg = code_seg->next;
    }
    i++;
  }

  if (!code_seg) {
    printf("No code segment. Stopping.\n");
    return -1;
  }
  code_seg->mem += ENTRY_POINT;

  void (*f)(unsigned long *);
  f = (void *)((unsigned long)code_seg->mem | 1);
  asm volatile(
               "mov r9, %0\n"
               "blx  %1\n"
               "bkpt\n"
               :
               : "r"(code_seg->mem), "r"(f)
               : "r9");

 return 0;

}    