#include "kint.h"
#include "../sekvm/hacl-20/Hacl_Ed25519.h"
#include "../sekvm/hacl-20/Hacl_AES.h"

u32 __hyp_text el2_load_module(u64 p_hdr, u64 mod_percpu, u64 mod_arch, u64 checklists, u32 entsize)
{   
  u32 err, i, pgnb;

  struct mod_sec_info secinfo[MAX_VERIFY_SECTION_SIZE];
  struct el2_mod_info mod;
  unsigned char mod_name[100];

  acquire_lock_host_kpt();
  el2_memset(&mod, 0, sizeof(struct el2_mod_info));
  el2_memset(&secinfo, 0, sizeof(struct mod_sec_info)*MAX_VERIFY_SECTION_SIZE);

  err = init_mapping(&mod, p_hdr, mod_arch);
  if (err)
		goto unlock;
  init_info(secinfo, &mod, checklists, entsize);

  if (mod.verify_size == 0)
		goto unlock;

  mod.modid = gen_modid();
  if (mod.modid == V_INVALID)
		goto unlock;

  el2_get_modinfo(&mod, mod_name);

  /* Signature Verification */
  pgnb = page_align(mod.verify_size) >> PAGE_SHIFT;
  mod.buff = alloc_tmp_buffer(pgnb);
  if (mod.buff == INVALID_MEM)
		goto fail_checksum;

  move_section(mod.buff, secinfo, 0U, 0U, entsize);
  err = verify_mod(mod.buff, mod.verify_size, mod_name);
  if (err)
		goto fail_checksum;

  err = update_section(&mod, secinfo, mod.buff, entsize);
  if (err)
		goto fail_checksum;

  err = simplify_symbol(&mod, mod_percpu);
  if (err)
		goto fail_checksum;

  err = relocate(&mod);
  if (err)
		goto fail_checksum;

  err = el2_fill_symtab(&mod, checklists, entsize);
  if (err)
		goto fail_checksum;

  el2_set_sec(&mod);
  update_ex_perm(&mod);
  refund_rw_perm(&mod, secinfo, entsize);
  release_lock_host_kpt();

  return mod.modid;

fail_checksum:
	remove_mod(mod.modid);
unlock:
 	refund_rw_perm(&mod, secinfo, entsize);
	release_lock_host_kpt();
	return V_INVALID;
}

const struct sig_info sig[5] = {
	{ "ipod", "b9b3c34ded3009acd3920dcb3da56666665dab0b9cc5d19ab3d5b4649518690c804688727e90d2f521cdb16c269acd42d22e5a05b94c1f3142d44d838b4a4b0b" },
	{ "libcrc32c", "da4b3392baa43eceee6ffcbe87c51ad851f028996d1ac7445e7dd2552c136cbdbe45d41948a3c5e41dfe43a9835c8e94a8c785907ac028c2290ba860644aa70f" },
	{ "xfs", "bdcc8409cac0b4719a11063366c44c0ec034f4faf6aa6476b6e19f5136e2d0c9b60a34a2346ca0a90c29455cb362e4a63eabed38c87a1aca77b254a9afe67f09" },
	{"crypto_engine","8d676c02b49db072a1bb279bec83e2e1d053a8d645cc0e941210af11cba0b67e7b88d29510180f0e1d2d17e5a7b95002ad3ef0c876ae9d998bebd8444c69e00c"},
	{"virtio_crypto", "01ae4c1834a88af09aa96cb91fa59cf7fbe0019898df7a232f821c116dec0228dea74583194e6d779ebfcbe1c554e039890b406bf899d1eb57bbe3132efe2a04"},
};

u32 __hyp_text verify_mod(u64 buff, size_t size, char *name)
{
	uint8_t public_key[32];
	uint8_t signature[64];
	uint8_t private_key[64];

	bool result;
	int i, id = -1;

	unsigned char *public_key_hex =
		"07f8993d1a43239a925ad3d02124b931b7f1d0531122f35d63c85cf79f3f4eca";
	unsigned char *private_key_hex =
		"100df9e44a5516fd053dc9ede29914b05d162c3faebbd1fb1897f8169c77a77bee33356625802cb7512453cd2719fec42100215369e30520979e7498506f010e";

	el2_hex2bin(public_key, public_key_hex, 32);
	el2_hex2bin(private_key, private_key_hex, 64);

	for (i = 0; i < ARRAY_SIZE(sig); i++) {
		if (!el2_strncmp(name, sig[i].name, el2_strlen(name))) {
			id = i;
			break;
		}
	}

	if (id != -1) {
		el2_hex2bin(signature, sig[id].signature_hex, 64);
		result = Hacl_Ed25519_verify(public_key, size, (uint8_t *)buff,
						signature);
	}

	return (result == true)? 0U: V_INVALID;
}

u32 __hyp_text gen_modid()
{
	u32 i;
	struct el2_mod *info;

	for (i = 0; i < EL2_MOD_INFO_SIZE; i++) {
		if (!get_mod_in_use(i)) {
			set_mod_in_use(i, true);
			return i;
		}
	}

	return V_INVALID;
}

void __hyp_text el2_get_modinfo(struct el2_mod_info *mod, char *mod_name)
{
	u32 info_idx, taglen;
	u64 size;
	char *name, *p;
	char *tmp;
	Elf_Shdr * infosec;

	taglen = el2_strlen("name");
	info_idx = find_sec(mod, ".modinfo");
	infosec = &mod->sechdrs[info_idx];
	size = infosec->sh_size;

	for (p = (char *) el1_va_to_el2(infosec->sh_addr); p; p = el2_next_str(p, &size))
	{
		if(el2_strncmp(p, "name", taglen) == 0 && p[taglen] == '=')
		{
			name = p + taglen + 1;
			el2_strncpy(mod_name, name, el2_strlen(name));
		}
	}
	return NULL;
}

void __hyp_text el2_set_sec(struct el2_mod_info *mod)
{
	struct el2_mod *info;

	info = (struct el2_mod *)get_mod_ref(mod->modid);
	el2_memcpy(&info->mod_sec, &mod->mod_section, sizeof(struct el2_mod_sec));
	el2_memcpy(&info->mod_tabs, &mod->mod_symtab, sizeof(struct el2_mod_tabs));
}

void __hyp_text mod_reloc_handler(u64 wdata, u64 rdata, u64 inst, u64 addr, u64 hsr)
{ 

  if (wdata == 0)
  { 
    handle_host_update(wdata, inst, addr, hsr);
    return;
  }

  v_panic();
}

u32 __hyp_text el2_free_module(u32 mod_id)
{ 
  char * mod_name; 
  u32 i;
  u32 ret = V_INVALID;

  acquire_lock_host_kpt();

  if (get_mod_in_use(mod_id)) {
		mark_rw_nx(mod_id, 0U);
		remove_mod(mod_id);
		ret = 0U;
  }

  release_lock_host_kpt();
  return ret;
}

u32 __hyp_text el2_free_mod_init(u32 mod_id)
{
  char * mod_name; 
  u32 last_idx;
  u32 ret = V_INVALID;

  acquire_lock_host_kpt();


  if (get_mod_in_use(mod_id)) {
	mark_rw_nx(mod_id, 1U);
	ret = 0U;
  }

  release_lock_host_kpt();
  return ret;
}
