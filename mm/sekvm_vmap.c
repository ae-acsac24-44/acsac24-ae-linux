/*
 * Copied from ./mm/vmalloc.c
 * FIXME: no unmap now
 */

#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/page.h>

extern void *host_alloc_mod_pages(unsigned short order, bool ro);

static int sekvm_vmap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, pgprot_t prot, int *nr, unsigned long flags)
{
	pte_t *pte;
	void *page;
	u64 pfn;

	/*
	 * nr is a running index into the array which helps higher level
	 * callers keep track of where we're up to.
	 */

	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {

		if (WARN_ON(!pte_none(*pte)))
			return -EBUSY;
		
		/* Only handle module page now */
		if (flags & VM_SEKVM_RO)
			page = host_alloc_mod_pages(0, true);
		else if (flags & VM_SEKVM_TXT)
			page = host_alloc_mod_pages(0, false);
		else
			return -ENOMEM;
		
		if(!page)	
			return -ENOMEM;
		
		pfn = __pa(page) >> PAGE_SHIFT;
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
		(*nr)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static int sekvm_vmap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, pgprot_t prot, int *nr, unsigned long flags)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (sekvm_vmap_pte_range(pmd, addr, next, prot, nr, flags))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static int sekvm_vmap_pud_range(p4d_t *p4d, unsigned long addr,
		unsigned long end, pgprot_t prot, int *nr, unsigned long flags)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc(&init_mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (sekvm_vmap_pmd_range(pud, addr, next, prot, nr, flags))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static int sekvm_vmap_p4d_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, pgprot_t prot, int *nr, unsigned long flags)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_alloc(&init_mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		if (sekvm_vmap_pud_range(p4d, addr, next, prot, nr, flags))
			return -ENOMEM;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int sekvm_vmap_page_range(unsigned long start, unsigned long end,
				   pgprot_t prot, unsigned long flags)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = start;
	int err = 0;
	int nr = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = sekvm_vmap_p4d_range(pgd, addr, next, prot, &nr, flags);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);

	return nr;
}
