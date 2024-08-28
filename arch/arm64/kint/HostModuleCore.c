#include "kint.h"

u64 __hyp_text el2_do_reloc(enum aarch64_reloc_op reloc_op, u64 place, u64 val)
{
	switch (reloc_op) {
	case RELOC_OP_ABS:
		return val;
	case RELOC_OP_PREL:
		return val - place;
	case RELOC_OP_PAGE:
		return (val & ~0xfff) - (place & ~0xfff);
	case RELOC_OP_NONE:
		return 0;
	}

	print_string("do_reloc: unknown relocation operation\n");
	return 0;
}

u32 __hyp_text el2_aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
				  u32 insn, u64 imm)
{
	u32 immlo, immhi, mask;
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
		imm >>= ADR_IMM_HILOSPLIT;
		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
		imm = immlo | immhi;
		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
		break;
	default:
		if (el2_aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			print_string("aarch64_insn_encode_immediate: unknown immediate encoding \n");
            return -1;
		}
	}

	/* Update the immediate field. */
	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}

u64 __hyp_text el2_module_emit_veneer_for_adrp(struct el2_mod_info *mod, void *loc, u64 val,
				bool in_init)
{	
	struct mod_plt_sec *pltsec = in_init ? &mod->arch->init :
	 						  &mod->arch->core;

	/* Maybe fix this by storing earlier */
	struct elf_shdr *plt_hdr = (struct elf64_shdr *)el1_va_to_el2(pltsec->plt);
	struct plt_entry *el1_plt = (struct plt_entry *)plt_hdr->sh_addr;
	struct plt_entry *plt = (struct plt_entry *)el1_va_to_el2((void *)el1_plt);

	int i = pltsec->plt_num_entries++;
	u32 mov0, mov1, mov2, br;
	int rd;

	if (pltsec->plt_num_entries > pltsec->plt_max_entries)
		{
			print_string("\rMax plt entry exceeded for module loading\n");
			return 0;
		}
	
	rd = el2_aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD,
					  le32_to_cpup((__le32 *)loc));
	
	mov0 = el2_aarch64_insn_gen_movewide(rd, (u16)~val, 0,
					 AARCH64_INSN_VARIANT_64BIT,
					 AARCH64_INSN_MOVEWIDE_INVERSE);
	
	mov2 = el2_aarch64_insn_gen_movewide(rd, (u16)(val >> 32), 32,
					 AARCH64_INSN_VARIANT_64BIT,
					 AARCH64_INSN_MOVEWIDE_KEEP);	

	br = el2_aarch64_insn_gen_branch_imm((u64)&plt[i].br, (u64)loc + 4,
					 AARCH64_INSN_BRANCH_NOLINK);

	plt[i] = (struct plt_entry){
			cpu_to_le32(mov0),
			cpu_to_le32(mov1),
			cpu_to_le32(mov2),
			cpu_to_le32(br)
	};

	return (u64)&el1_plt[i];
}

u64 __hyp_text el2_module_emit_plt_entry(struct el2_mod_info *mod, void *loc, const Elf64_Rela *rela,
			  Elf64_Sym *sym, bool in_init)
{
	struct mod_plt_sec *pltsec = in_init? &mod->arch->init :
	 						  &mod->arch->core;

	/* Maybe fix this by storing earlier */
	struct elf_shdr *plt_hdr = (struct elf64_shdr *)el1_va_to_el2(pltsec->plt);
	struct plt_entry *el1_plt = (struct plt_entry *)plt_hdr->sh_addr;
	struct plt_entry *plt = (struct plt_entry *)el1_va_to_el2((void *)el1_plt);

	int i = pltsec->plt_num_entries;
	u64 val = sym->st_value + rela->r_addend;

	plt[i] = el2_get_plt_entry(val);

	/*
	 * Check if the entry we just created is a duplicate. Given that the
	 * relocations are sorted, this will be the last entry we allocated.
	 * (if one exists).
	 *
	 * Since we don't know either (plt + i) or (plt + i - 1) not on the
	 * same page as plt, just proceed with it...
	 */
	struct plt_entry *plt_i = (struct plt_entry *)el1_va_to_el2((void *)(el1_plt + i));
	struct plt_entry *plt_ii = (struct plt_entry *)el1_va_to_el2((void *)(el1_plt + i - 1));
	if (i > 0 && el2_plt_entries_equal(plt_i, plt_ii))
		return (u64)&el1_plt[i - 1];

	pltsec->plt_num_entries++;
	if (pltsec->plt_num_entries > pltsec->plt_max_entries)
		return 0;

	return (u64)&el1_plt[i];
}


u32 __hyp_text find_sec(struct el2_mod_info *mod, const char *name)
{
	unsigned int i;

	for (i = 1; i < mod->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &mod->sechdrs[i];
		/* Alloc bit cleared means "ignore it." */
		if (!el2_strcmp(mod->secstring + shdr->sh_name, name))
			return i;
	}
	return 0;
}

bool __hyp_text el2_find_symbol(struct find_symbol_arg *fsa)
{	
	int i,j ;
	u32 max_modid;
	struct el2_mod_tabs *mod_symtab;

	const struct ksym_tab ksymtab =  get_kernel_symtab();

	const struct symsearch arr[] = {
		{ __el2_va(ksymtab.start_ksymtab), __el2_va(ksymtab.stop_ksymtab), NULL,
		  NOT_GPL_ONLY, false },
		{ __el2_va(ksymtab.start_ksymtab_gpl), __el2_va(ksymtab.stop_ksymtab_gpl), NULL,
		  GPL_ONLY, false },
	};

	for (i = 0; i < ARRAY_SIZE(arr); i++)
		if (el2_find_symbol_in_section(&arr[i], fsa))
			return true;

	for (i = 0; i < EL2_MOD_INFO_SIZE; i++) {
		if (get_mod_in_use(i)) {
			mod_symtab = (struct el2_mod_tabs *)get_mod_tab(i);
			struct symsearch arr[] = {
				{ mod_symtab->syms, mod_symtab->syms + mod_symtab->num_syms,
						NULL, NOT_GPL_ONLY, false },
				{ mod_symtab->gpl_syms, mod_symtab->gpl_syms + mod_symtab->num_gpl_syms,
						NULL, GPL_ONLY, false },
			};

			for (j = 0; j < ARRAY_SIZE(arr); j++)
				if (el2_find_symbol_in_section(&arr[j], fsa))
					return true;
		}
	}

	return false;
}


int __hyp_text el2_reloc_data(enum aarch64_reloc_op op, void *place, u64 el1_place, u64 val, int len)
{
	s64 sval = el2_do_reloc(op, el1_place, val);

	switch (len) {
	case 16:
		*(s16 *)place = sval;
		if (sval < S16_MIN || sval > U16_MAX)
			return -ERANGE;
		break;
	case 32:
		*(s32 *)place = sval;
		if (sval < S32_MIN || sval > U32_MAX)
			return -ERANGE;
		break;
	case 64:
		*(s64 *)place = sval;
		break;
	default:
		return 0;
	}
	return 0;
}

u64 __hyp_text get_page_entry(u64 el1_base)
{
	
	u64 ttbr, idx, ptr, entry, pt_leaf;
	u64 pfn, kpt_index; 

	pt_leaf = 1; 

	ttbr = read_sysreg(ttbr1_el1) & ((1UL << 40UL) - 1UL); 
	idx = pgd_idx(el1_base) * sizeof(pgd_t);
	ptr = ttbr | idx;
	entry = pt_load(COREVISOR, ptr);  
	
	ptr = phys_page(entry); 
	idx = pud_idx(el1_base) * sizeof(pud_t); 
	ptr |= idx; 
	entry = pt_load(COREVISOR, ptr); 
	pt_leaf = entry & TYPE_BIT_MASK;
	if (!pt_leaf)
		return ptr; 

	ptr = phys_page(entry); 
	idx = pmd_idx(el1_base) * sizeof(pmd_t); 
	ptr |= idx; 
	entry = pt_load(COREVISOR, ptr); 
	pt_leaf = entry & TYPE_BIT_MASK;
	if (!pt_leaf)
		return ptr; 

	ptr = phys_page(entry); 
	idx = pte_idx(el1_base) * sizeof(pte_t); 
	ptr |= idx; 

	return ptr; 
}

