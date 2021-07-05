#include "elf_helper.h"
#include <string.h>

void init_dynparser(struct Dyn_parser_helper *dyn_p) {
  dyn_p->dt_pltgot = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_hash = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_symtab = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_jmprel = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_rel = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_strtab = calloc(sizeof(struct Dyn_section), 1);
}

struct Dyn_parser_helper* parse_dynamic(void* mem, size_t base_addr) {
  struct Dyn_parser_helper *dyn_p = calloc(sizeof(struct Dyn_parser_helper), 1);;
  init_dynparser(dyn_p);
  Elf_Dyn *curr = ((Elf_Dyn *) mem);
  
  // DT_NULL is always the last entry
  while (curr->d_tag != DT_NULL) {
    switch (curr->d_tag)
    {
    case DT_PLTGOT:
      dyn_p->dt_pltgot->mem = curr->d_val + base_addr;
      printf("DT_PLTGOT: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_pltgot->mem);
      break;

    case DT_HASH:
      dyn_p->dt_hash->mem = curr->d_val + base_addr;
      printf("DT_HASH: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_hash->mem);
      // The second Elf_Word in DT_HASH holds the number of entry in DT_SYMTAB
      Elf_Sword nbentry_symtab = *((Elf_Sword*)(dyn_p->dt_hash->mem) + 1);
      printf("Number of entry in DT_SYMTAB: %d\n", nbentry_symtab);
      if (dyn_p->dt_symtab->size == 0) {
        // We did not yet reached DT_SYMENT which holds the size of one entry
        dyn_p->dt_symtab->size = nbentry_symtab;
      } else {
        // We already reached DT_SYMENT which holds the size of one entry
        // Let's multiply it with the number of entry
        dyn_p->dt_symtab->size *= nbentry_symtab;
        printf("DT_SYMTAB total size: 0x%2x\n", dyn_p->dt_symtab->size);
      }
      break;

    case DT_SYMENT:
      // The d_val of DT_SYMENT holds the size of one entry in DT_SYMTAB
      printf("Entry size of DT_SYMTAB: %d\n", curr->d_val);
      if (dyn_p->dt_symtab->size == 0) {
        // We did not yet reached DT_HASH which holds the number of entry
        dyn_p->dt_symtab->size = curr->d_val;
      } else {
        // We already reached DT_HASH which holds the number of entry
        // Let's multiply it with the number of entry
        dyn_p->dt_symtab->size *= curr->d_val;
        printf("DT_SYMTAB total size: 0x%2x\n", dyn_p->dt_symtab->size);
      }
      break;

    case DT_RELSZ:
      dyn_p->dt_rel->size = curr->d_val;
      printf("DT_REL size is: 0x%2x\n", curr->d_val);
      break;

    case DT_PLTRELSZ:
      dyn_p->dt_jmprel->size = curr->d_val;
      printf("DT_JMPREL size is: 0x%2x\n", curr->d_val);
      break;

    case DT_STRSZ:
      dyn_p->dt_strtab->size = curr->d_val;
      printf("DT_STRTAB size is: 0x%2x\n", curr->d_val);
      break;
    
    case DT_SYMTAB:
      dyn_p->dt_symtab->mem = curr->d_val + base_addr;
      printf("DT_SYMTAB: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_symtab->mem);
      break;
      
    case DT_JMPREL:
      dyn_p->dt_jmprel->mem = curr->d_val + base_addr;
      printf("DT_JMPREL: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_jmprel->mem);
      break;

    case DT_REL:
      dyn_p->dt_rel->mem = curr->d_val + base_addr;
      printf("DT_REL: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_rel->mem);
      break;

    case DT_STRTAB:
      dyn_p->dt_strtab->mem = curr->d_val + base_addr;
      printf("DT_STRTAB: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_strtab->mem);
      break;

    default:
      break;
    }
    curr+=1;
  }
  return dyn_p;
}

struct Symbol* parse_symbols(struct Dyn_section *dt_symtab, struct Dyn_section *dt_strtab, size_t base_addr) {
  struct Symbol *first = calloc(sizeof(struct Symbol), 1);

  struct Symbol *curr_symbol = first;  
  // First symbol always null ?
  Elf_Sym *curr_elf = ((Elf_Sym *) dt_symtab->mem) + 1;

  first->name = malloc(strlen(curr_elf->st_name + dt_strtab->mem));
  strcpy(first->name, curr_elf->st_name + dt_strtab->mem);
  printf("name : %s\n", first->name);
  first->real_addr = curr_elf->st_value;
  if (first->real_addr == NULL) {
    first->flags = 1;
  } else {
    first->real_addr += base_addr;
    first->flags = 0;
  }
  printf("got_addr : %p\n", first->got_addr);
  printf("real_addr : %p\n", first->real_addr);
  printf("external : %d\n\n",  first->flags );

  curr_elf+=1;

  while (curr_elf < dt_symtab->mem + dt_symtab->size) {
    struct Symbol *temp = calloc(sizeof(struct Symbol), 1);
    temp->name = malloc(strlen(curr_elf->st_name + dt_strtab->mem));
    strcpy(temp->name, curr_elf->st_name + dt_strtab->mem);
    printf("name : %s\n", temp->name);
    temp->real_addr = curr_elf->st_value;
    if (temp->real_addr == NULL) {
      temp->flags = 1;
    } else {
      temp->real_addr += base_addr;
      temp->flags = 0;
    }
    printf("got_addr : %p\n", temp->got_addr);
    printf("real_addr : %p\n", temp->real_addr);
    printf("external : %d\n\n",  temp->flags );

    curr_symbol->next = temp;
    curr_symbol = temp;

    curr_elf+=1; 
  }

  return first;
}