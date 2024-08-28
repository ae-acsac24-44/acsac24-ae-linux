#include "hypsec.h"

static void inline advance_pc(void)
{
	u64 pc = read_sysreg(elr_el2);
	write_sysreg(pc + 4, elr_el2);
}

/*
 * 1. The base address of translation table of EL0 regime should owned by HOSTVISOR
 * 2. The base address of translation table of EL0 should not point to kernel space(TTBR1_EL1)
 * We do optimization on context switches, so no longer perform ttbr0 update at here,
 * see HostPtSwitch.c
 */
static void __hyp_text handle_ttbr0(u64 val)
{
	__hyp_panic();
/*
	u64 pfn,baddr;
	u32 owner;

#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	baddr = val & ~TTBR_ASID_MASK;
#else
	baddr = val;
#endif

	pfn = baddr / PAGE_SIZE;
	owner = get_pfn_owner(pfn);
	
	u64 swapper = get_host_ttbr1();
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	u64 tramp = swapper - (PAGE_SIZE + RESERVED_TTBR0_SIZE);	// tramp_pg_dir 
	if( owner == HOSTVISOR && baddr != swapper && baddr != tramp ){
#else
	if( owner == HOSTVISOR && baddr != swapper ){
#endif
		asm volatile(
        	"msr TTBR0_EL1, %0\n"
			:: "r" (val)
			:
		);
	} else {
		__hyp_panic();
	}
*/
}

/*
 * 1. The base address of translation table of EL1 regime should owned by HOSTVISOR
 * 2. The value of base address of translation table after booting should only be
 * 	  the kernel page or trampoline page
 */
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
static void __hyp_text handle_ttbr1(u64 val)
{
	u64 pfn, baddr;
	u64 swapper;
	u32 owner;

	baddr = val & ~TTBR_ASID_MASK;		/*TCR_EL1.A1 = 1, ASID defined by ttbr1.ASID*/
	pfn = baddr / PAGE_SIZE;
	
	owner = get_pfn_owner(pfn);
	if( owner == HOSTVISOR ){
		swapper = get_host_ttbr1();									// swapper_pg_dir
		u64 tramp = swapper - (PAGE_SIZE + RESERVED_TTBR0_SIZE);	// tramp_pg_dir 
		bool user_flag = val & USER_ASID_FLAG;
		
		if( ( baddr == tramp &&  user_flag ) || ( baddr == swapper && !user_flag ) ){

			asm volatile(
        		"msr TTBR1_EL1, %0\n"
				:: "r" (val)
				:
			);

		} else {
				__hyp_panic();
		}
	} else {
		__hyp_panic();
	}
}
#else
static inline void __hyp_text handle_ttbr1(u64 val)
{
	__hyp_panic();
}
#endif

void __hyp_text handle_host_sys_regs(unsigned long host_lr,
				struct s2_host_regs *host_regs)
{
	u32 esr;
	int Rt;
	esr = read_sysreg(esr_el2);
	set_per_cpu_host_regs((u64)host_regs);

	Rt = (esr >> 5) & 0x1f;
	bool is_write = !(esr & 1);
	u64 val = 0;
	unsigned long ret = 0;

	if (!is_write)
	/*
	 * The registers is written by host
	 * with instruction MSR and traps to EL2,
	 * hence the bit should be 1 in ESR_EL2
	 */
		__hyp_panic();


	val = get_host_regs(Rt);
	ret = sec_el2_handle_sys_reg(esr);

	switch (ret) {
		case TTBR0_EL1:
			handle_ttbr0(val);
			break;
		case TTBR1_EL1:
			handle_ttbr1(val);
			break;
		default:
			/*
			 * Extend handler if needed. By default, the remaining
			 * system register will not modified after booting.
			 * Remaining Register:
			 * SCTLR_EL1, TCR_EL1, ESR_EL1, FAR_EL1, ASFR0_EL1, ASFR_EL1,
			 * MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1
			 */
			__hyp_panic();
			break;
	}

	/*Move PC to next instruction and continue execution when return to address in ELR_EL2*/
	advance_pc();
}
