#include "kint.h"

u64 __hyp_text elf_size(u64 vhdr)
{
	Elf64_Ehdr *hdr;
	u64 size;

	hdr = (Elf64_Ehdr *)el1_va_to_el2(vhdr);
	size = hdr->e_shoff + (hdr->e_shentsize * hdr->e_shnum);
	return size;
}

bool __hyp_text within_temporary_image(struct el2_mod_info *mod, u64 addr, u64 size)
{
	u64 end;

	end = page_align(addr + size);

	return ((addr >= mod->vhdr) && (end <= (mod->vhdr + mod->size))) ? true : false;
}

struct mod_sec_info __hyp_text init_sec(u32 idx, struct el2_mod_info *mod)
{
	struct mod_sec_info secinfo;
	u64 perm;
	u32 page_nb, err;

	el2_memset(&secinfo, 0, sizeof(struct mod_sec_info));

	Elf64_Shdr *shdr = &mod->sechdrs[idx];
	struct verinfo *vinfo = &secinfo.vinfo;

	secinfo.base = shdr->sh_addr;
	
	vinfo->size = shdr->sh_size;
	vinfo->flags = shdr->sh_flags;
	vinfo->align_size = shdr->sh_addralign? :1;
	vinfo->info = shdr->sh_info;
	vinfo->type = shdr->sh_type;
	vinfo->link = shdr->sh_link;

	if (vinfo->type == SHT_SYMTAB) {
		mod->index.sym = idx;
		mod->index.str = shdr->sh_link;
		mod->strtab = (char *)mod->hdr + mod->sechdrs[mod->index.str].sh_offset;
	}

	/*
	 * Remap sections that locacted in final memory layout
	 * to write-protected before authenticate.
	 */
	if (!within_temporary_image(mod, secinfo.base, vinfo->size))
	{
		page_nb = page_align(vinfo->size) >> PAGE_SHIFT;
		perm = pgprot_val(PAGE_S2);
		err = remap_host_mod_page_range(secinfo.base, page_nb, EL1_AUTH, perm, 3U, 0U);
		if (err)
			secinfo.base = 0UL;
	}

	return secinfo;
}

u32 __hyp_text remap_host_mod_page(u64 pfn, u32 owner, u64 perm, u32 level, u32 clear)
{
	u64 new_pte;
	u32 i, subowner;

	subowner = get_pfn_subowner(pfn);


	if (owner == subowner)
		return 0U;

	if (get_pfn_owner(pfn) != HOSTVISOR || (subowner != EL1_AUTH && subowner != NONE))
		return V_INVALID;
		
	clear_pfn_host(pfn);

	if (clear) {
		clear_phys_page(pfn);
		__flush_dcache_area(__el2_va(pfn << PAGE_SHIFT), PAGE_SIZE);
	}

	new_pte = (pfn * PAGE_SIZE) | perm;
	mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, level, new_pte);

	set_pfn_subowner(pfn, owner);

	return 0;
}

u32 __hyp_text remap_host_mod_page_range(u64 base, u32 page_nb, u32 owner,
				u64 perm, u32 level, u32 clear)
{
	u64 pfn;
	u32 i, ret;

	for (i = 0; i < page_nb; i++) {
		pfn = translate_to_phys(base + i * PAGE_SIZE) / PAGE_SIZE;
		ret = remap_host_mod_page(pfn, owner, perm, level, clear);
		if (ret == V_INVALID)
			return ret;
	}
	return 0;
}

u32 __hyp_text get_offset_check(struct mod_sec_info *secinfo, u64 *base, u64 *size, 
				u64 mask, u32 *start, u32 end)
{
	u32 i;
	long ret;

	*base = 0UL;
	*size = 0UL;

	for (i = *start; i < end; i++) {
		if ((secinfo[i].vinfo.flags & SHF_WAX) != mask) {
			if(*base != 0UL)
				return i;
		} else {
			if(*base == 0UL) {
				*start = i;
				*base = secinfo[i].base;
			}

			ret = el2_align(*size, secinfo[i].vinfo.align_size);
			if ((*base + ret) != secinfo[i].base) {
					return V_INVALID;
			}
			*size = ret + secinfo[i].vinfo.size;
		}
	}

	return end;
}

const struct kernel_symbol *__hyp_text el2_resolve_symbol(const char *name)
{
	u64 owner_modid;
	const struct kernel_symbol *ksym;
	int err;

	struct find_symbol_arg fsa = {
		.name = name,
		.gplok = true, // assume to be true
		.sym = NULL,
	};

	el2_find_symbol(&fsa);
	
	return fsa.sym;
}


int __hyp_text reloc_insn_movw_el2(enum aarch64_reloc_op op, __le32 *place,
				   u64 el1_place, u64 val, int lsb,
				   enum aarch64_insn_movw_imm_type imm_type)
{
	u64 imm;
	s64 sval;
	u32 insn = le32_to_cpu(*place); 

	sval = el2_do_reloc(op, el1_place, val);
	imm = sval >> lsb;

	if (imm_type == AARCH64_INSN_IMM_MOVNZ) {
		/*
    	 * For signed MOVW relocations, we have to manipulate the
    	 * instruction encoding depending on whether or not the
    	 * immediate is less than zero.
    	 */
		insn &= ~(3 << 29);
		if (sval >= 0) {
			/* >=0: Set the instruction to MOVZ (opcode 10b). */
			insn |= 2 << 29;
		} else {
			/*
    		 * <0: Set the instruction to MOVN (opcode 00b).
    		 *     Since we've masked the opcode already, we
    		 *     don't need to do anything other than
    		 *     inverting the new immediate field.
    		 */
			imm = ~imm;
		}
	}

	/* Update the instruction with the new encoding. */
	insn = el2_aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn,
						 imm); // Not an issue

	*place = cpu_to_le32(insn); // This is hte actual update

	if (imm > U16_MAX)
		return -ERANGE;
	return 0;
}

int __hyp_text reloc_insn_imm_el2(enum aarch64_reloc_op op, __le32 *place,
				  u64 el1_place, u64 val, int lsb, int len,
				  enum aarch64_insn_imm_type imm_type)
{
	u64 imm, imm_mask;
	s64 sval;
	u32 insn = le32_to_cpu(*place);
	/* Calculate the relocation value. */
	sval = el2_do_reloc(op, el1_place, val);
	sval >>= lsb;

	/* Extract the value bits and shift them to bit 0. */
	imm_mask = (BIT(lsb + len) - 1) >> lsb;
	imm = sval & imm_mask;

	/* Update the instruction's immediate field. */
	insn = el2_aarch64_insn_encode_immediate(imm_type, insn, imm);

	*place = cpu_to_le32(insn);

	/*
	 * Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0.
	 */

	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

	/*
	 * Overflow has occurred if the upper bits are not all equal to
	 * the sign bit of the value.
	 */
	if ((u64)(sval + 1) >= 2)
		return -ERANGE;

	return 0;
}

u32 __hyp_text reloc_insn_adrp_el2(struct el2_mod_info *mod, __le32 *place, u64 el1_place,
			u64 val, bool in_init)
{
	u32 insn;
	u32 tmp;

	if (!IS_ENABLED(CONFIG_ARM64_ERRATUM_843419) ||
	    !cpus_have_const_cap(ARM64_WORKAROUND_843419) ||
	    ((u64)place & 0xfff) < 0xff8) {
		tmp = reloc_insn_imm_el2(RELOC_OP_PAGE, place, el1_place, val,
					 12, 21, AARCH64_INSN_IMM_ADR);
		return tmp;
	}

	/* patch ADRP to ADR if it is in range */
	if (!reloc_insn_imm_el2(RELOC_OP_PREL, place, el1_place, val & ~0xfff,
				0, 21, AARCH64_INSN_IMM_ADR)) {
		insn = le32_to_cpu(*place);
		insn &= ~BIT(31);
	} else {
		/* out of range for ADR -> emit a veneer */
		val = el2_module_emit_veneer_for_adrp(mod, place, val & ~0xfff, in_init);
		if (!val)
			return -ENOEXEC;
		insn = el2_aarch64_insn_gen_branch_imm((u64)place, val,
						   AARCH64_INSN_BRANCH_NOLINK);
	}
	*place = cpu_to_le32(insn);
	return 0;
}

int __hyp_text apply_relocate_add_el2(struct el2_mod_info *mod, u32 relsec)
{
	u32 i;
	int ovf;
	bool overflow_check, in_init;
	Elf64_Sym *sym, *el1_sym;
	void *loc, *el1_loc;
	Elf64_Shdr *sechdrs;
	u64 val, symidx;

	sechdrs = mod->sechdrs;
	symidx = mod->index.sym;

	Elf64_Rela *rel = (void *)el2_mod_va(sechdrs[relsec].sh_addr, mod); 

	in_init = !el2_strncmp(mod->secstring + sechdrs[sechdrs[relsec].sh_info].sh_name,
					".init", 5);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {

		el1_loc = (void*)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;

		loc = (void *) el1_va_to_el2(el1_loc);

		el1_sym = (Elf64_Sym *)sechdrs[symidx].sh_addr
					 + ELF64_R_SYM(rel[i].r_info);

		sym = (Elf64_Sym *)el1_va_to_el2(el1_sym);

		val = sym->st_value + rel[i].r_addend;

		overflow_check = true;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		/* Null relocations. */
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			ovf = 0;
			break;

		/* Data relocations. */
		case R_AARCH64_ABS64:
			overflow_check = false;
			ovf = el2_reloc_data(RELOC_OP_ABS, loc, el1_loc, val, 64);
			break;
		case R_AARCH64_ABS32:
			ovf = el2_reloc_data(RELOC_OP_ABS, loc, el1_loc, val, 32);
			break;
		case R_AARCH64_ABS16:
			ovf = el2_reloc_data(RELOC_OP_ABS, loc, el1_loc, val, 16);
			break;
		case R_AARCH64_PREL64:
			overflow_check = false;
			ovf = el2_reloc_data(RELOC_OP_PREL, loc, el1_loc, val, 64);
			break;
		case R_AARCH64_PREL32:
			ovf = el2_reloc_data(RELOC_OP_PREL, loc, el1_loc, val, 32);
			break;
		case R_AARCH64_PREL16:
			ovf = el2_reloc_data(RELOC_OP_PREL, loc, el1_loc, val, 16);
			break;

		/* MOVW instruction relocations. */
		case R_AARCH64_MOVW_UABS_G0_NC:
			overflow_check = false;
		case R_AARCH64_MOVW_UABS_G0:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 0,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_UABS_G1_NC:
			overflow_check = false;
		case R_AARCH64_MOVW_UABS_G1:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 16,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_UABS_G2_NC:
			overflow_check = false;
		case R_AARCH64_MOVW_UABS_G2:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 32,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_UABS_G3:
			/* We're using the top bits so we can't overflow. */
			overflow_check = false;
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 48,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_SABS_G0:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 0,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G1:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 16,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G2:
			ovf = reloc_insn_movw_el2(RELOC_OP_ABS, loc, el1_loc, val, 32,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G0_NC:
			overflow_check = false;
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 0,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_PREL_G0:
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 0,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G1_NC:
			overflow_check = false;
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 16,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_PREL_G1:
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 16,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G2_NC:
			overflow_check = false;
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 32,
					      AARCH64_INSN_IMM_MOVKZ);
			break;
		case R_AARCH64_MOVW_PREL_G2:
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 32,
					      AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G3:
			/* We're using the top bits so we can't overflow. */
			overflow_check = false;
			ovf = reloc_insn_movw_el2(RELOC_OP_PREL, loc, el1_loc, val, 48,
					      AARCH64_INSN_IMM_MOVNZ);
			break;

		/* Immediate instruction relocations. */
		case R_AARCH64_LD_PREL_LO19:
			ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 2, 19,
					     AARCH64_INSN_IMM_19);
			break;
		case R_AARCH64_ADR_PREL_LO21:
			ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 0, 21,
					     AARCH64_INSN_IMM_ADR);
			break;

		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			overflow_check = false;
		case R_AARCH64_ADR_PREL_PG_HI21:
			ovf = reloc_insn_adrp_el2(mod, loc, el1_loc, val, in_init);
			if (ovf && ovf != -ERANGE)
				return ovf;
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm_el2(RELOC_OP_ABS, loc, el1_loc, val, 0, 12,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST16_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm_el2(RELOC_OP_ABS, loc, el1_loc, val, 1, 11,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST32_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm_el2(RELOC_OP_ABS, loc, el1_loc, val, 2, 10,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST64_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm_el2(RELOC_OP_ABS, loc, el1_loc, val, 3, 9,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST128_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm_el2(RELOC_OP_ABS, loc, el1_loc, val, 4, 8,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_TSTBR14:
			ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 2, 14,
					     AARCH64_INSN_IMM_14);
			break;
		case R_AARCH64_CONDBR19:
			ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 2, 19,
					     AARCH64_INSN_IMM_19);
			break;
		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26:
			ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 2, 26,
					     AARCH64_INSN_IMM_26);

			if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
			    ovf == -ERANGE) {
				val = el2_module_emit_plt_entry(mod, loc, &rel[i], sym, in_init);
				if (!val)
					return -ENOEXEC;
				ovf = reloc_insn_imm_el2(RELOC_OP_PREL, loc, el1_loc, val, 2,
						     26, AARCH64_INSN_IMM_26);
			}
			break;

		default:
			print_string("\rdefault\n");
			return -1;
		}

		if (overflow_check && ovf == -ERANGE)
		{
			goto overflow;
		}

	}
	return 0;

overflow:
	print_string("\rOverflow\n");
	return -1;
}

void __hyp_text mark_ex(u64 el1_base, u64 pgnb, u32 enabled_ex)
{	
	int i; 
	u64 entry, ptr, pfn; 
	for(i = 0; i < pgnb; i ++)
	{
		ptr = get_page_entry(el1_base + i * PAGE_SIZE); 
		pfn = ptr >> PAGE_SHIFT; 
		entry = pt_load(COREVISOR, ptr);
		if (enabled_ex)
			entry &= ~DCPTR_EL1_PXN_BLOCK_MASK;
		else
			entry |= DCPTR_EL1_PXN_BLOCK_MASK;
		pt_store(COREVISOR, ptr, entry);
		
	}                                                                                  
	kvm_tlb_flush_vmid_ipa_host(pfn * PAGE_SIZE);
	return;
}

void __hyp_text refund_host_mod_page(u64 base, u32 pgnb)
{
	u64 pfn, perm, new_pte;
	u32 owner; 
	u32 i, clr;

	for (i = 0; i < pgnb; i++) {
		pfn = translate_to_phys(base + i * PAGE_SIZE) / PAGE_SIZE;
		set_pfn_subowner(pfn, NONE);

		clr = check_clear_pfn_host(pfn);

		if(clr)
		{
			if (clr == 2U)
			{
				perm = pgprot_val(SECT_S2_KERNEL);
				new_pte = (pfn * PAGE_SIZE) | perm;
				mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 2U, new_pte);
			}
			else if (clr == 3U)
			{
				perm = pgprot_val(PAGE_S2_KERNEL);
				new_pte = (pfn * PAGE_SIZE) | perm;
				mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 3U, new_pte);
			}
		}
	}
}
