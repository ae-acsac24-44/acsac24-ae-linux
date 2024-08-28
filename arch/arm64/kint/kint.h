#include "../sekvm/hypsec.h"
#include "../sekvm/MmioOps.h"

#define STXR_OPCODE_MASK 0xFFE08000
#define STXR_OPCODE1 0x88000000
#define STXR_OPCODE2 0xC8000000
/* FIXME: hardcoded for inst 'stp xzr, xzr, [x[0:31], #0]'*/
#define STP_XZR_MASK 0xFFFFFC1F
#define STP_XZR_INST 0xA9007C1F
/* FIXME: 'stp' instruction only when 'wback = false && imm7 == 0' from now'*/
#define STP_OPCODE_MASK 0xFFFF8000
#define STP_OPCODE 0xA9000000

#define offset_shift (12)
#define offset_mask ((UL(1) << offset_shift) - 1)

#define TYPE_BIT_SHIFT 1
#define TYPE_BIT_MASK (UL(0x1) << TYPE_BIT_SHIFT)

#define ESR_EL2_ISV_SHIFT 24
#define ESR_EL2_ISV_MASK (UL(0x1) << ESR_EL2_ISV_SHIFT)

#define DCPTR_EL1_TB_SHIFT (1)
#define DCPTR_EL1_TB_MASK (UL(0x1) << DCPTR_EL1_TB_SHIFT)

#define STXR_Rt_SHIFT 0
#define STXR_Rt_MASK (UL(0x1F) << STXR_Rt_SHIFT)

#define STXR_Rs_SHIFT 16
#define STXR_Rs_MASK (UL(0x1F) << STXR_Rs_SHIFT)

#define STXR_Rn_SHIFT 5
#define STXR_Rn_MASK (UL(0x1F) << STXR_Rn_SHIFT)

#define STP_Rt_SHIFT 0
#define STP_Rt_MASK (UL(0x1F) << STP_Rt_SHIFT)

#define STP_Rt2_SHIFT 10
#define STP_Rt2_MASK (UL(0x1F) << STP_Rt2_SHIFT)

#define DCPTR_EL1_AP_TABLE_SHIFT (61)
#define DCPTR_EL1_AP_TABLE_MASK (UL(3) << DCPTR_EL1_AP_TABLE_SHIFT)

#define DCPTR_EL1_XN_TABLE_SHIFT (60)
#define DCPTR_EL1_XN_TABLE_MASK (UL(1) << DCPTR_EL1_XN_TABLE_SHIFT)

#define DCPTR_EL1_PXN_TABLE_SHIFT (59)
#define DCPTR_EL1_PXN_TABLE_MASK (UL(1) << DCPTR_EL1_PXN_TABLE_SHIFT)

#define DCPTR_EL1_AP_BLOCK_SHIFT (6)
#define DCPTR_EL1_AP_BLOCK_MASK (UL(0x3) << DCPTR_EL1_AP_BLOCK_SHIFT)

#define DCPTR_EL1_XN_BLOCK_SHIFT (54)
#define DCPTR_EL1_XN_BLOCK_MASK (UL(1) << DCPTR_EL1_XN_BLOCK_SHIFT)

#define DCPTR_EL1_PXN_BLOCK_SHIFT (53)
#define DCPTR_EL1_PXN_BLOCK_MASK (UL(1) << DCPTR_EL1_PXN_BLOCK_SHIFT)

#define is_kpt(x) (x <= EL1_PTE && x >= EL1_PGD)
#define is_mod(x) (x == EL1_MOD_txt || x == EL1_MOD_ro)

#define points_to_table(x, y)                                                  \
	((x >= EL1_PUD && x <= EL1_PMD && y == 1) || (x == EL1_PGD))

#define points_to_leaf(x, y)                                                   \
	((x >= EL1_PUD && x <= EL1_PMD && y == 0) || (x == EL1_PTE))

#define kint_pfn_pmd(pfn) (pfn << PAGE_SHIFT) & HUGE_PMD_MASK
#define kint_pfn_pud(pfn) (pfn << PAGE_SHIFT) & HUGE_PUD_MASK
#define kint_mk_pmd(pfn, prot) ((kint_pfn_pmd(pfn)) | prot)
#define kint_mk_pud(pfn, prot) ((kint_pfn_pud(pfn)) | prot)

#define el2_mapped(x) (x >= 0x40040000000 && x <= 0x40140000000)

#define dword_size 4
#define qword_size 8
#define page_align(x) ((x + PAGE_SIZE - 1UL) & ~(PAGE_SIZE - 1UL))
#define dword_align(x) ((x + dword_size - 1UL & ~(dword_size - 1UL)))
#define el2_align(x, a) ((x + a - 1UL & ~(a - 1UL)))
#define el2_mod_va(x, mod) (x - mod->el_diff)

#define MAX_VERIFY_SECTION_SIZE 100
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG-1))
#define EL2_GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define ELF_ST_BIND(x)		((x) >> 4)

#define ADR_IMM_HILOSPLIT 2
#define ADR_IMM_SIZE SZ_2M
#define ADR_IMM_LOMASK ((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK ((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT 29
#define ADR_IMM_HISHIFT 5
#define AARCH64_BREAK_MON 0xd4200000
#define FAULT_BRK_IMM 0x100
#define AARCH64_BREAK_FAULT (AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))

#define SHF_WAX (SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE)

enum aarch64_insn_movw_imm_type {
	AARCH64_INSN_IMM_MOVNZ,
	AARCH64_INSN_IMM_MOVKZ,
};

enum aarch64_reloc_op {
	RELOC_OP_NONE,
	RELOC_OP_ABS,
	RELOC_OP_PREL,
	RELOC_OP_PAGE,
};

struct verinfo {
	u64 size;
	u64 flags;
	u64 align_size;
	u64 info;
	u64 type;
	u64 link;
};

struct sig_info {
	char name[100];
	char signature_hex[128];
};

struct mod_sec_info {
	u64 base;
	u64 buff_offset;
	struct verinfo vinfo;
};

struct el2_mod_info {
	Elf64_Ehdr *hdr;
	Elf64_Shdr *sechdrs;
	char *secstring;
	char *strtab;
	u64 el_diff;
	u64 buff;
	u64 size;
	u64 verify_size;
	u64 vhdr;
	u32 modid;
	// arm64 only
	struct mod_arch_specific *arch;
	struct el2_mod_sec mod_section;
	struct el2_mod_tabs mod_symtab;
	struct {
		unsigned int sym, str, pcpu;
	} index;
};

struct find_symbol_arg {
	/* Input */
	const char *name;
	bool gplok;

	/* Output */
	const struct kernel_symbol *sym;
};

/*
 * HostModule
 */

u32 __hyp_text verify_mod(u64 buff, size_t size, char *name);
u32 __hyp_text gen_modid(void);
void __hyp_text el2_get_modinfo(struct el2_mod_info *mod, char *mod_name);
void __hyp_text el2_set_sec(struct el2_mod_info *mod);
void __hyp_text mod_reloc_handler(u64 wdata, u64 rdata, u64 inst,  u64 addr, u64 hsr);

/*
 * HostModuleOps
 */

u32 __hyp_text init_mapping(struct el2_mod_info *mod, u64 vhdr, u64 mod_arch);
void __hyp_text init_info(struct mod_sec_info *secinfo, struct el2_mod_info *mod,
				u64 checklists, u32 entsize);
void __hyp_text move_section(u64 buff, struct mod_sec_info *secinfo, u32 rev,
				u32 start, u32 end);
u32 __hyp_text remap_and_rewrite(u64 base, u64 size, u32 owner,
				struct mod_sec_info *secinfo, u32 start, u32 end);
u32 __hyp_text update_section(struct el2_mod_info *mod,
				struct mod_sec_info *secinfo, u64 buff, u32 entsize);
int __hyp_text simplify_symbol(struct el2_mod_info *mod,
				u64 mod_percpu);
int __hyp_text relocate(struct el2_mod_info *mod);
u32 __hyp_text el2_fill_symtab(struct el2_mod_info *mod, u64 checklists, u32 entsize);
void __hyp_text update_ex_perm(struct el2_mod_info *mod);

void __hyp_text refund_rw_perm(struct el2_mod_info *mod,
		struct mod_sec_info *secinfo, u32 entsize);
void __hyp_text mark_rw_nx(u32 mod_idx, u32 is_init);
void __hyp_text remove_mod(u32 mod_idx); 

/*
 * HostModuleAux
 */

u64 __hyp_text elf_size(u64 vhdr);
bool __hyp_text within_temporary_image(struct el2_mod_info *mod, u64 addr, u64 size);
struct mod_sec_info __hyp_text init_sec(u32 idx, struct el2_mod_info *mod);
u32 __hyp_text remap_host_mod_page(u64 pfn, u32 owner, u64 perm, u32 level, u32 clear);
u32 __hyp_text remap_host_mod_page_range(u64 base, u32 page_nb, u32 owner,
				u64 perm, u32 level, u32 clear);
u32 __hyp_text get_offset_check(struct mod_sec_info *secinfo, u64 *base, u64 *size,
				u64 mask, u32 *start, u32 end);
const struct kernel_symbol *__hyp_text el2_resolve_symbol(const char *name);

int __hyp_text reloc_insn_movw_el2(enum aarch64_reloc_op op, __le32 *place,
				   u64 el1_place, u64 val, int lsb,
				   enum aarch64_insn_movw_imm_type imm_type);
int __hyp_text reloc_insn_imm_el2(enum aarch64_reloc_op op, __le32 *place,
				  u64 el1_place, u64 val, int lsb, int len,
				  enum aarch64_insn_imm_type imm_type);
u32 __hyp_text reloc_insn_adrp_el2(struct el2_mod_info *mod, __le32 *place,
				   u64 el1_loc, u64 val, bool in_init);
int __hyp_text apply_relocate_add_el2(struct el2_mod_info *mod, u32 relsec);

void __hyp_text mark_ex(u64 base, u64 pgnb, u32 enabled_ex);
void __hyp_text refund_host_mod_page(u64 base, u32 pgnb);
/*
 * HostModuleCore
 */

u32 __hyp_text find_sec(struct el2_mod_info *mod, const char *name);
bool __hyp_text el2_find_symbol(struct find_symbol_arg *fsa);

u64 __hyp_text el2_do_reloc(enum aarch64_reloc_op reloc_op, u64 place, u64 val);
int __hyp_text el2_reloc_data(enum aarch64_reloc_op op, void *place, u64 el1_place, u64 val, int len);
u32 __hyp_text el2_aarch64_insn_encode_immediate(
	enum aarch64_insn_imm_type type, u32 insn, u64 imm);
u64 __hyp_text el2_module_emit_veneer_for_adrp(struct el2_mod_info *mod, void *loc,
					       u64 val, bool in_init);
u64 __hyp_text el2_module_emit_plt_entry(struct el2_mod_info *mod, void *loc, const Elf64_Rela *rela,
			  Elf64_Sym *sym, bool in_init);

u64 __hyp_text get_page_entry(u64 el1_base); 

/*
 * HostModuleCoreAux
 */

u64 __hyp_text alloc_tmp_buffer(u64 pgnum);
int __hyp_text el2_cmp_name(const void *va, const void *vb);
bool __hyp_text el2_find_symbol_in_section(const struct symsearch *syms, void *data);

int __hyp_text el2_aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
					      u32 *maskp, int *shiftp);
u32 __hyp_text el2_aarch64_insn_decode_register(enum aarch64_insn_register_type type,
					u32 insn);
u32 __hyp_text el2_aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
			      int imm, int shift,
			      enum aarch64_insn_variant variant,
			      enum aarch64_insn_movewide_type type);
u32 __hyp_text el2_aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
					  enum aarch64_insn_branch_type type);
struct plt_entry __hyp_text el2_get_plt_entry(u64 val);
bool __hyp_text el2_plt_entries_equal(const struct plt_entry *a,
				     const struct plt_entry *b);

/*
 * HostModuleExt
 */

u32 __hyp_text el2_aarch64_insn_encode_register(enum aarch64_insn_register_type type,
					u32 insn,
					enum aarch64_insn_register reg);
long __hyp_text el2_branch_imm_common(unsigned long pc, unsigned long addr,
				     long range);
/*
 * Helper
 */

void __hyp_text *el2_bsearch(const void *key, const void *base, size_t num,
			     size_t size,
			     int (*cmp)(const void *key, const void *elt));
u64 __hyp_text el2_strcmp(const char *a, const char *b);
u64 __hyp_text el2_strncmp(const char *s1, const char *s2, u32 n);
u64 __hyp_text el2_strlen(const char *str); 
char * __hyp_text el2_next_str(char *string, u64 *secsize);
char* __hyp_text el2_strncpy(char* dest, const char* source, u32 num);

/*
 * HostKpt Functions are in hypsec.h
 */

/*
 * HostKptOps
 */

void __hyp_text unmapping_handler(u64 rdata, u64 wdata, u64 inst,
				  u64 fault_ipfn, u64 hsr);
void __hyp_text mapping_handler(u64 wdata, u64 inst, u64 fault_ipfn, u64 hsr);
void __hyp_text update_handler(u64 rdata, u64 wdata, u64 inst, u64 fault_ipfn,
			       u64 hsr);

/*
 * HostKptAux
 */

u32 __hyp_text handle_host_update(u64 wdata, u32 inst, u64 fault_ipfn, u32 hsr);
u32 __hyp_text handle_host_new_page(u64 pfn, u32 subid, u32 vmid);
void __hyp_text handle_host_remove_page(u64 pfn, u32 vmid);
void __hyp_text handle_host_leaf_update(u64 wdata, u32 w_subowner, u32 inst,
					u64 fault_ipfn, u32 hsr);

/*
 * HostKptCore
 */

u64 __hyp_text el1_va_to_el2(u64 el1_va);
void __hyp_text handle_host_update_write(u64 wdata, u64 fault_ipa, u32 len);
u64 __hyp_text handle_host_update_read(u64 fault_ipa, u32 len);
void __hyp_text stxr_write_handler(u64 wdata, u64 inst, u64 va);
void __hyp_text stp_write_handler(u64 inst, u64 va);
u32 __hyp_text get_kpt_shift(u32 subid);
u32 __hyp_text check_clear_pfn_host(u64 pfn);
u32 __hyp_text check_if_clear_range_host(u64 start, u64 size);

/*
 * HostKptCoreAux
 */

u64 __hyp_text fetch_rdata(u64 addr);
u64 __hyp_text fetch_wdata(u64 hsr, u64 inst);
u64 __hyp_text fetch_instruction(void);
u32 __hyp_text stxr_write_handler_asm(u32 wdata, u64 fault_ipa);

/*
 * el1_kpt
 */

void __hyp_text init_text(void);
void __hyp_text init_data(void);
u64 __hyp_text init_set_section_subowner(u64 entry, u32 subid);
u32 __hyp_text is_kcode(u64 entry, u64 size);


static u64 inline get_kim_voff(void)
{
	struct el2_data *el2_data = kern_hyp_va((void *)&el2_data_start);
	return el2_data->kimage_voff;
};

static struct ksym_tab inline get_kernel_symtab(void)
{
	struct el2_data *el2_data = kern_hyp_va((void *)&el2_data_start);
	return el2_data->kernel_symtab;
}

static u64 inline get_mod_ref(u32 modid)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return (u64) &el2_data->mod_info[modid];
}

static bool inline get_mod_in_use(u32 modid)
{
	struct el2_data *el2_data = kern_hyp_va((void *)&el2_data_start);
	return el2_data->mod_info[modid].in_use;
}

static void inline set_mod_in_use(u32 modid, bool in_use)
{
	struct el2_data *el2_data = kern_hyp_va((void *)&el2_data_start);
	el2_data->mod_info[modid].in_use = in_use;
}

static u64 inline get_mod_tab(u32 modid)
{
	struct el2_data *el2_data = kern_hyp_va((void *)&el2_data_start);
	return &el2_data->mod_info[modid].mod_tabs;
}
