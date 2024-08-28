#include "kint.h"

u32 __hyp_text init_mapping(struct el2_mod_info *mod, u64 vhdr, u64 mod_arch)
{
	u32 i, pgnb, err;
	u64 hdr, size, pfn, target;
	u64 host_perm, hyp_perm;

	size = elf_size(vhdr);

	pgnb = page_align(size) >> PAGE_SHIFT;

	hdr = alloc_remap_addr(pgnb);

	hyp_perm = pgprot_val(PAGE_HYP);
	host_perm = pgprot_val(PAGE_S2);

	for (i = 0; i < pgnb; i++) {
		pfn = translate_to_phys(vhdr + (i * PAGE_SIZE)) / PAGE_SIZE;
		target = hdr + i * PAGE_SIZE;

		err = remap_host_mod_page(pfn, EL1_AUTH, host_perm, 3U , 0U);
		if (err)
			return err;
		mmap_s2pt(COREVISOR, target, 3UL, (pfn * PAGE_SIZE) | hyp_perm);
	}

	mod->vhdr = vhdr;
	mod->hdr = (Elf64_Ehdr *)hdr;
	mod->size = page_align(size);
	mod->sechdrs = (Elf64_Shdr *)((void *)mod->hdr + mod->hdr->e_shoff);
	mod->el_diff = vhdr - hdr;
	mod->secstring = (char *)((void *)mod->hdr +
				  mod->sechdrs[mod->hdr->e_shstrndx].sh_offset);
	mod->index.sym = 0;

	mod->arch = (struct mod_arch_specific *)el1_va_to_el2(mod_arch);

	return 0U;
}

void __hyp_text init_info(struct mod_sec_info *secinfo, struct el2_mod_info *mod,
				u64 checklists, u32 entsize)
{
	u32 i;
	mod->verify_size = 0;

	if (entsize > mod->hdr->e_shnum)
		return;

	unsigned int *el2_checklists;
	el2_checklists = (unsigned int *)el1_va_to_el2(checklists);

	for (i = 0; i < entsize; i++)
	{
		if (el2_checklists[i] == 0 || el2_checklists[i] >= mod->hdr->e_shnum) {
			mod->verify_size = 0;
			return;
		}

		secinfo[i] = init_sec(el2_checklists[i], mod);
		if (secinfo[i].base == 0UL) {
			mod->verify_size = 0;
			return;
		}

		mod->verify_size += sizeof(struct verinfo);
		if(secinfo[i].vinfo.type != SHT_NOBITS)	// mostly plt section
			mod->verify_size += secinfo[i].vinfo.size;
	}

	/* symbol table section should be included in verification */
	if (mod->index.sym == 0) {
		mod->verify_size = 0;
		return;
	}

	/* pcpu */
	mod->index.pcpu = find_sec(mod, ".data..percpu");

	return;
}

/*
 * Looks dirty... Reverse the role when perform write back
 * rev == 0: addr -> buf
 * rev == 1: buf -> addr
 */
void __hyp_text move_section(u64 buff, struct mod_sec_info *secinfo, u32 rev,
				u32 start, u32 end)
{
	int i;
	void *addr;
	u64 base, size;
	u64 aligned, size_to_write;
	u32 vinfo_size = sizeof(struct verinfo);

	for (i = start; i < end; i++) {

		if (!rev) {
			el2_memcpy((void *)buff, &secinfo[i].vinfo, vinfo_size);
			buff += vinfo_size;
		}

		if(secinfo[i].vinfo.type == SHT_NOBITS)
				continue;

		base = secinfo[i].base;
		size = secinfo[i].vinfo.size;

		if (!rev) {
			secinfo[i].buff_offset = buff;
		} else {
			buff = secinfo[i].buff_offset;
			secinfo[i].buff_offset = INVALID64;
		}

		aligned = page_align(base);
		size_to_write = aligned - base;

		while (size > size_to_write) {
			addr = el1_va_to_el2(base);
			if (!rev)
				el2_memcpy((void *)buff, addr, size_to_write);
			else
				el2_memcpy(addr, (void *)buff, size_to_write);

			size -= size_to_write;
			base += size_to_write;
			buff += size_to_write;
			size_to_write = PAGE_SIZE;
		}

		addr = el1_va_to_el2(base);
		if (!rev)
			el2_memcpy((void *)buff, addr, size);
		else
			el2_memcpy(addr, (void *)buff, size);
		buff += size;
	}
}

u32 __hyp_text remap_and_rewrite(u64 base, u64 size, u32 owner,
				struct mod_sec_info *secinfo, u32 start, u32 end)
{
	u64 perm;
	u32 page_nb, ret;

	/* FIXME: 4KB page from now */
	u64 ex_perm = pgprot_val(PAGE_S2_KCODE);
	/* FIXME: temprorary marked as RW */
	u64 ro_perm = pgprot_val(PAGE_S2_KERNEL);

	perm = (owner == EL1_MOD_txt)? ex_perm : ro_perm;
	page_nb = page_align(size) >> PAGE_SHIFT;

	/* remmap */
	ret = remap_host_mod_page_range(base, page_nb, owner, perm, 3U, 1U);
	if (ret == V_INVALID)
		return ret;

	/* rewrite */
	move_section(0UL, secinfo, 1U, start, end);

	return 0;
}


u32 __hyp_text update_section(struct el2_mod_info *mod, 
				struct mod_sec_info *secinfo, u64 buff, u32 entsize)
{
	/*
	 * Checklists
	 * +------+--------+-----------+-------------+--------------+
	 * | text | rodata | init text | init rodata | rela_section |
	 * +------+--------+-----------+-------------+--------------+
	 * In this case, we may only need to check execution permission.
	 * Note that we must do verification before rewrite the sections,
	 * so that we can truely remap the pages and assign the subowner.
	 */
	u32 ret, start, end, i, owner;
	u64 mask;

	static unsigned long const ex_mask = SHF_EXECINSTR | SHF_ALLOC;
	static unsigned long const ro_mask = SHF_ALLOC;
	struct el2_mod_sec *s = &mod->mod_section;

	start = 0;

	u64 *secptrs[3][2] = {
		{ &s->text_base, &s->text_size },
		{ &s->ro_base, &s->ro_size },
		{ &s->init_text_base, &s->init_text_size }
		// { &s->init_ro_base, &s->init_ro_size }
	};


	for (i = 0; i < 3; i++) {

		mask = (i % 2 == 0)? ex_mask : ro_mask;
		owner = (i % 2 == 0)? EL1_MOD_txt : EL1_MOD_ro;

		/* check */
		end = get_offset_check(secinfo, secptrs[i][0], secptrs[i][1],
						mask, &start, entsize);
		if (end == V_INVALID) {
			return ret;
		}

		/* remmap and rewrite */
		if (*secptrs[i][0] != 0UL && start < end) {
			ret = remap_and_rewrite(*secptrs[i][0], *secptrs[i][1],
							owner, secinfo, start, end);
			if (ret == V_INVALID) {
				return end;
			}
			start = end;
		}
	}

	return 0;
}


int __hyp_text simplify_symbol(struct el2_mod_info *mod,
				u64 mod_percpu)
{
	Elf_Shdr *symsec = &mod->sechdrs[mod->index.sym];
	Elf_Sym *sym = (Elf_Sym *)el1_va_to_el2((u64)symsec->sh_addr);
	unsigned long secbase;
	unsigned int i;
	const struct kernel_symbol *ksym;

	for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
		const char *name = mod->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {
		case SHN_COMMON: 
		case SHN_ABS:
		case SHN_LIVEPATCH:
			break;
		case SHN_UNDEF:
			ksym = el2_resolve_symbol(name);
			/* Ok if resolved.  */
			if (ksym && !IS_ERR(ksym)) {
				sym[i].st_value = ksym->value;
				break;
			}

			if (!ksym && ELF_ST_BIND(sym[i].st_info) == STB_WEAK)
					break;

			print_string("Unknown symbol\n");
			return -1;

		default:
			/* Divert to percpu allocation if a percpu var. */
			if (sym[i].st_shndx == mod->index.pcpu)
				secbase = mod_percpu;
			else
				secbase = mod->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
	}
	return 0;
}

int __hyp_text relocate(struct el2_mod_info *mod)
{
	u32 i;
	int err = 0;

	for (i = 0; i < mod->hdr->e_shnum; i++) {
		unsigned int infosec = mod->sechdrs[i].sh_info;
		/* Not a valid relocation section? */
		if (infosec >= mod->hdr->e_shnum)
			continue;

		/* Don't bother with non-allocated sections */
		if (!(mod->sechdrs[infosec].sh_flags & SHF_ALLOC))
			continue;

		/* Livepatch relocation sections are applied by livepatch */
		if (mod->sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH)
			continue;

		if (mod->sechdrs[i].sh_type == SHT_REL)
			continue;

		else if (mod->sechdrs[i].sh_type == SHT_RELA)
			err = apply_relocate_add_el2(mod, i);

		if (err < 0)
			break;
	}

	return err;
}

u32 __hyp_text el2_fill_symtab(struct el2_mod_info *mod, u64 checklists, u32 entsize)
{
	u32 i;
	unsigned int *el2_checklists;

	el2_checklists = (unsigned int *)el1_va_to_el2(checklists);

	/* exported ksymtab */
	for (i = 1; i < entsize; i++)
	{
		Elf64_Shdr *shdr = &mod->sechdrs[i];
		if ((shdr->sh_flags & SHF_WAX) == SHF_ALLOC) /* read-only */
		{
			if(!el2_strcmp(mod->secstring + shdr->sh_name, "__ksymtab"))
			{
				mod->mod_symtab.syms = el1_va_to_el2(shdr->sh_addr);
				mod->mod_symtab.num_syms = shdr->sh_size;

				if (shdr->sh_size > PAGE_SIZE) {
					/* FIXME: maximum only 1 page from now */
					return V_INVALID;
				}
			}
			else if(!el2_strcmp(mod->secstring + shdr->sh_name, "__ksymtab_gpl"))
			{
				mod->mod_symtab.gpl_syms = el1_va_to_el2(shdr->sh_addr);
				mod->mod_symtab.num_gpl_syms = shdr->sh_size;

				if (shdr->sh_size > PAGE_SIZE) {
					/* FIXME: maximum only 1 page from now */
					return V_INVALID;
				}
			}
		}
	}
	return 0U;
}

void __hyp_text update_ex_perm(struct el2_mod_info *mod)
{
	u32 init_page, text_page, ro_page;
	u64 init_base, init_size, text_base, text_size, ro_base, ro_size;

	init_base = mod->mod_section.init_text_base;
	init_size = mod->mod_section.init_text_size;
	init_page = page_align(init_size) / PAGE_SIZE;

	text_base = mod->mod_section.text_base;
	text_size = mod->mod_section.text_size;
	text_page = page_align(text_size) / PAGE_SIZE;

	mark_ex(init_base, init_page, 1U);
	mark_ex(text_base, text_page, 1U);
}

void __hyp_text refund_rw_perm(struct el2_mod_info *mod,
		struct mod_sec_info *secinfo, u32 entsize)
{
	u64 perm;
	u32 page_nb, i;

	perm = pgprot_val(PAGE_S2_KERNEL);
	page_nb = page_align(mod->size) >> PAGE_SHIFT;

	/* Temporary Image */
	remap_host_mod_page_range(mod->vhdr, page_nb, 0U, perm, 3U, 0U);

	
	/* Final Image */
	for (i = 0; i < entsize; i++) {
		if (secinfo[i].buff_offset != INVALID64
			&& !within_temporary_image(mod, secinfo[i].base, secinfo[i].vinfo.size))
		{
			page_nb = page_align(secinfo[i].vinfo.size) >> PAGE_SHIFT;
			remap_host_mod_page_range(secinfo[i].base, page_nb, 0U, perm, 3U, 0U);
		}
	}
}

void __hyp_text mark_rw_nx(u32 mod_idx, u32 is_init)
{
	struct el2_mod *info;
	u64 text_base, text_size;
	u64 ro_base, ro_size;
	u32 ro_page, text_page;

	info = (struct el2_mod *)get_mod_ref(mod_idx);

	if (is_init) {
		text_base = info->mod_sec.init_text_base;
		text_size = info->mod_sec.init_text_size;
		text_page = page_align(text_size) / PAGE_SIZE;
	} else {
		text_base = info->mod_sec.text_base;
		text_size = info->mod_sec.text_size;
		text_page = page_align(text_size) / PAGE_SIZE;
	}
	// Add in init RO for this 
	// ro_base = info->mod_sec.ro_base;
	// ro_size = info->mod_sec.ro_size;
	// ro_page = page_align(ro_size) / PAGE_SIZE;

	mark_ex(text_base, text_page, 0U);
	refund_host_mod_page(text_base, text_page);
	// refund_host_mod_page(ro_base, ro_page);
}

void __hyp_text remove_mod(u32 mod_idx)
{
	struct el2_mod *info;

	info = (struct el2_mod *)get_mod_ref(mod_idx);
	el2_memset(info, 0, sizeof(struct el2_mod));
}

