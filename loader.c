#include <stdbool.h>
#include <stdio.h>
#include "loader.h"
#include "elf_helper.h"
#include "hook_functions.h"

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

  // Hook some functions that we are interested in
  printf("\nHook functions: \n");
  hook_functions(t_lib->symbols);

  // Dynamic link of symbols
  printf("\nLink symbols: \n");
  link_symbols(t_let->symbols, t_lib->symbols);

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

  // Allocate heap
  // What is a good value for heap_size ?
  size_t t_heap_size = 0x10000;
  void *t_heap = mmap(HEAP_ADDR, t_heap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if (t_heap == MAP_FAILED) {
    perror("Error in mmap stack");
    exit(-1);
  }
  struct Symbol *app_heap_base = find_symbol_from_name(t_let->symbols, "app_heap_base");
  struct Symbol *app_heap_limit = find_symbol_from_name(t_let->symbols, "app_heap_limit");

  *((Elf_Addr *)(app_heap_base->got_addr)) = (Elf_Addr)(t_heap);
  app_heap_base->real_addr = t_heap;
  *((Elf_Addr *)(app_heap_limit->got_addr)) = (Elf_Addr)(t_heap + t_heap_size);
  app_heap_limit->real_addr = t_heap + t_heap_size;

  register void *sp asm ("sp");
  // What value to use as stack size ?
  size_t t_stack_size = 0x10000;

  struct Symbol *app_stack_base = find_symbol_from_name(t_let->symbols, "app_stack_base");
  struct Symbol *app_stack_limit = find_symbol_from_name(t_let->symbols, "app_stack_limit");

  *((Elf_Addr *)(app_stack_base->got_addr)) = (Elf_Addr)(sp);
  app_stack_base->real_addr = sp;
  *((Elf_Addr *)(app_stack_limit->got_addr)) = (Elf_Addr)(sp + t_stack_size);
  app_stack_limit->real_addr = sp + t_stack_size;

  printf("\n[+] Start trustlet execution\n\n");
  asm volatile(
               "mov r9, %0\n"
               "blx  %1\n"
               "bkpt\n"
               :
//               : "r"(code_seg->mem), "r"(BASE_ADDR_CMNLIB + 0x391d) // To test qsee_log from cmnlib
               : "r"(code_seg->mem), "r"(BASE_ADDR_TRUSTLET + 0x169) // To test qsee_log from htc_drmprov trustlet
//               : "r"(code_seg->mem), "r"(entry_point)
               : "r9");

  return 0;
}    