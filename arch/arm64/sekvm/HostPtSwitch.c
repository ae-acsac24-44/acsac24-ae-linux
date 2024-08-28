#include "hypsec.h"
#ifdef CONFIG_KERNEL_INT
#include "../kint/kint.h"
#endif

#ifdef CONFIG_ARM64_PA_BITS_52
#define phys_to_ttbr(addr)	(((addr) | ((addr) >> 46)) & TTBR_BADDR_MASK_52)
#else
#define phys_to_ttbr(addr)	(addr)
#endif

static inline bool check_if_swapper(u64 baddr)
{
	u64 swapper;
	bool user_flag = false;

	if (baddr == 0UL)
		return false;

	swapper = get_host_ttbr1();
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	user_flag = baddr & USER_ASID_FLAG;
#endif
	return (baddr == swapper && !user_flag);
}

static inline bool is_swapper_or_tramp(u64 baddr)
{
	u64 tramp, swapper;

	if (baddr == 0UL)
		return false;

	swapper = get_host_ttbr1();
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	tramp = swapper - (PAGE_SIZE + RESERVED_TTBR0_SIZE);
#else
	tramp = 0UL;
#endif
	return ((baddr == swapper) || (baddr == tramp));
}

static inline void el2_host_set_reserved_ttbr0_asm(void)
{
	unsigned long ttbr = phys_to_ttbr(get_host_zero_page());

	asm volatile(
		"msr TTBR0_EL1, %0\n"
		:
		: "r" (ttbr)
		:
	);
}

static inline void el2_do_switch_mm_asm(u64 ttbr0, u64 ttbr1, u64 asid)
{
	asm volatile(
#ifdef CONFIG_ARM64_SW_TTBR0_PAN
		"bfi	%1, %0, #48, #16\n"		// set the ASID field in TTBR0
#endif
		"bfi	%2, %0, #48, #16\n"		// set the ASID
		"msr	TTBR1_EL1, %2\n"		// in TTBR1 (since TCR.A1 is set)
		"msr	TTBR0_EL1, %1\n"		// now update TTBR0
		:
		: "r" (asid), "r" (ttbr0), "r" (ttbr1)
		:
	);
}

u32 __hyp_text el2_do_switch_mm(u64 ttbr0, u64 asid)
{
	u64 baddr0, baddr1;
	u64 hcr;
	u32 owner0, owner1, subowner0;

	/* ttbr0_el1 */
#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	baddr0 = ttbr0 & ~TTBR_ASID_MASK;
#else
	baddr0 = ttbr0;
#endif

	/* ttbr1_el1 */
	baddr1 = read_sysreg(ttbr1_el1) & ~TTBR_ASID_MASK;

	// acquire_lock_s2page();

	owner0 = get_pfn_owner(baddr0 >> PAGE_SHIFT);
	owner1 = get_pfn_owner(baddr1 >> PAGE_SHIFT);

#ifdef CONFIG_KERNEL_INT
	subowner0 = get_pfn_subowner(baddr0 >> PAGE_SHIFT);
#endif

	hcr = read_sysreg(hcr_el2);

	if ((hcr & HCR_TVM) == 0)
	/*
	 * Do not trap to EL2 anymore, let the host
	 * handle the mm switch itself.
	 */
		goto fail;

	if (owner0 == HOSTVISOR && owner1 == HOSTVISOR)
	{
		if (check_if_swapper(baddr1) && !is_swapper_or_tramp(baddr0)
#ifdef CONFIG_KERNEL_INT
			&& (subowner0 == EL0_PGD) /* EL0_PGD */
#endif
		   )
		{
			/* No translations will be possible via TTBR0. */
			el2_host_set_reserved_ttbr0_asm();
			el2_do_switch_mm_asm(phys_to_ttbr(ttbr0), baddr1, asid);
		}
		else
		{
			__hyp_panic();
		}
	}
	else
	{
		__hyp_panic();
	}

	// release_lock_s2page();
	return 0;

fail:
	// release_lock_s2page();
	return -1;
}

#ifdef CONFIG_KERNEL_INT
void __hyp_text el2_do_alloc_el0_pgd(u64 addr)
{
	u64 pfn;
	u32 owner, subowner;

	pfn = phys_page(addr) >> PAGE_SHIFT;

	acquire_lock_s2page();

	owner = get_pfn_owner(pfn);
	subowner = get_pfn_subowner(pfn);

	if (owner != HOSTVISOR)
	{
		print_string("pgd: not a host page.\n");
		// v_panic();
	}
	else if (!subowner)
	{
		handle_host_new_page(pfn, EL0_PGD, owner);
	}

	release_lock_s2page();
}

void __hyp_text el2_do_free_el0_pgd(u64 addr)
{
	u64 pfn;
	u32 owner, subowner;

	pfn = phys_page(addr) >> PAGE_SHIFT;

	acquire_lock_s2page();

	owner = get_pfn_owner(pfn);
	subowner = get_pfn_subowner(pfn);

	if (owner != HOSTVISOR)
	{
		print_string("pgd: not a host page.\n");
		// v_panic();
	}

	if (subowner == EL0_PGD)
	{
		handle_host_remove_page(pfn, owner);
	}

	release_lock_s2page();
}

#endif
