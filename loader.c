#include "loader.h"
#include "elf_helper.h"
#include <stdbool.h>

struct Trustlet * map_trustlet(char *path, size_t base_addr) {
  struct Trustlet *t_let = parse_elf(path, base_addr);
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
    return t_let;
  }

  t_let->e_entry += base_addr;
  printf("\nDEBUG: dynamic parsing step:\n\n");
  struct Dyn_parser_helper *res = parse_dynamic(dyn_seg->mem, base_addr);
  
  printf("\nDEBUG: symbols parsing step:\n\n");
  t_let->symbols = parse_symbols(res->dt_symtab, res->dt_strtab, base_addr);
  
  printf("\nDEBUG: parsing DT_REL step:\n\n");
  parse_rel(t_let, res->dt_rel, base_addr);
  
  printf("\nDEBUG: parsing DT_JMPREL step:\n\n");
  parse_jmprel(t_let->symbols, res->dt_jmprel, base_addr);

  printf("\n~ THAT'S ALL FOLKS ~\n");
  return t_let;
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("usage: trustlet_path\n");
    return 0;
  }

  struct Trustlet *t_let = map_trustlet(argv[1], BASE_ADDR_TRUSTLET);
  // TODO : Get path from argv[2] ?
  //        Support 32/64 bits
  struct Trustlet *t_lib = map_trustlet("cmnlib", BASE_ADDR_CMNLIB);

  // Seek to entry point
  struct Segment *code_seg = t_let->segments;
  bool stop = false;
  // Find dynamic segment
  while (code_seg && !stop) {
    if (code_seg->type == PT_LOAD && (code_seg->perm & (PF_X))) {
      stop = true;
    } else {
      code_seg = code_seg->next;
    }
  }

  if (!code_seg) {
    printf("No code segment. Stopping.\n");
    return -1;
  }

  Elf_Addr entry_point = 0;
  struct Symbol *celf_invoke = find_symbol_from_name(t_let->symbols, "CElfFile_invoke");
  if (!celf_invoke) {
    entry_point = t_let->e_entry;
  } else {
    entry_point = celf_invoke->real_addr;
  }

  asm volatile(
               "mov r9, %0\n"
               "blx  %1\n"
               "bkpt\n"
               :
               : "r"(code_seg->mem), "r"(entry_point)
               : "r9");

 return 0;

}    