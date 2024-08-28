#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/page.h>

#include <linux/spinlock.h>
#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/types.h>


#define HYP_NO_ORDER	USHRT_MAX

/*
 * FIXME: It would be better to add an extra header file
 * and migrate some code to another locations
 */

struct hyp_page {
	unsigned short refcount;
	unsigned short order;
};

/* reserved memory base */
u64 host_s1_mem_base;
u64 host_s1_mem_size;
static u64 host_s1_mem_pfn;

/* reserved memory region for kernel page table */
u64 host_s1_pgtable_mem_base;
u64 host_s1_pgtable_mem_size;
u64 host_s1_pgtable_early_mem_base;

static u64 host_s1_sparse_mem_base;
static u64 host_s1_sparse_mem_size;

/*
 * reserved memory region for kernel module
 * 1. rodata section
 * 2. init text or text section
 */
u64 host_s1_module_ro_base;
u64 host_s1_module_ro_size;

u64 host_s1_module_text_base;
u64 host_s1_module_text_size;

static u64 __sekvm_vmemmap;

/* Reservation */
void  __init early_sekvm_hyp_reserve(void);
void  __init sekvm_hyp_reserve(void);

struct hyp_pool {
	/*
	 * Spinlock protecting concurrent changes to the memory pool as well as
	 * the struct hyp_page of the pool's pages until we have a proper atomic
	 * API at EL2.
	 */
	spinlock_t lock;
	struct list_head free_area[MAX_ORDER];
	phys_addr_t range_start;
	phys_addr_t range_end;
	unsigned short max_order;
};

/* Allocation */
void *host_alloc_pt_pages(unsigned short order);
void host_free_pt_pages(unsigned long addr);
void *host_alloc_mod_pages(unsigned short order, bool ro);
static void *host_alloc_pages(struct hyp_pool *pool, unsigned short order);


/* API */
static inline u64 host_s1_pgtable_pages(void);
static inline u64 host_s1_module_pages(void);
static inline u64 host_s1_vmemmap_pages(u64 vmemmap_entsize);
void host_split_page(struct hyp_page *page);
void host_get_page(struct hyp_pool *pool, void *addr);
void host_put_page(struct hyp_pool *pool, void *addr);

/* Finalise */
/* FIXME: Used pages cannot be freed */
int host_s1_pool_init(struct hyp_pool *pool, u64 base, u64 size);
void host_s1_pool_finalise(void);

static struct hyp_pool host_s1_pgtable_pool;
static struct hyp_pool host_s1_module_ro_pool;
static struct hyp_pool host_s1_module_text_pool;

#define sekvm_vmemmap ((struct hyp_page *)__sekvm_vmemmap)

#define __sekvm_va(phys)	__va(phys)
#define __sekvm_pa(virt)	(phys_addr_t)__pa(virt)

#define sekvm_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define sekvm_pfn_to_phys(pfn)	((phys_addr_t)((pfn) << PAGE_SHIFT))
#define sekvm_phys_to_page(phys)	(&sekvm_vmemmap[sekvm_phys_to_pfn(phys - host_s1_mem_base)])
#define sekvm_virt_to_page(virt)	sekvm_phys_to_page(__sekvm_pa(virt))
#define sekvm_virt_to_pfn(virt)	sekvm_phys_to_pfn(__sekvm_pa(virt))

#define sekvm_page_to_pfn(page)	  (((u64)(page) - (u64)(sekvm_vmemmap)) / sizeof(struct hyp_page)) + host_s1_mem_pfn
#define sekvm_page_to_phys(page)  sekvm_pfn_to_phys((sekvm_page_to_pfn(page)))
#define sekvm_page_to_virt(page)	__sekvm_va(sekvm_page_to_phys(page))
#define sekvm_page_to_pool(page)	(((struct hyp_page *)page)->pool)

static inline u64 host_s1_pgtable_pages(void)
{
	return (PMD_SIZE * (256 + 128)) >> PAGE_SHIFT;
}

static inline u64 host_s1_module_pages(void)
{
	return (PMD_SIZE * 128) >> PAGE_SHIFT;
}

static inline u64 host_s1_vmemmap_pages(u64 vmemmap_entsize)
{
	u64 start, end;

	start = host_s1_mem_base;

	if (!start)
			return 0;

	host_s1_mem_pfn = sekvm_phys_to_pfn(start);

	if (!host_s1_sparse_mem_base)
		end = host_s1_mem_base + (host_s1_module_pages() << PAGE_SHIFT);
	else
		end = host_s1_sparse_mem_base + host_s1_sparse_mem_size;

	if (end <= start)
			return 0;

	return (((end - start) >> PAGE_SHIFT) * vmemmap_entsize);
}

static inline int sekvm_hyp_page_count(void *addr)
{
	struct hyp_page *p = sekvm_virt_to_page(addr);

	return p->refcount;
}

static inline void *sekvm_phys_to_virt(phys_addr_t phys)
{
	return __sekvm_va(phys);
}

static inline phys_addr_t sekvm_virt_to_phys(void *addr)
{
	return __sekvm_pa(addr);
}

static struct hyp_page *__find_buddy_nocheck(struct hyp_pool *pool,
					     struct hyp_page *p,
					     unsigned short order)
{
	phys_addr_t addr = sekvm_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);

	/*
	 * Don't return a page outside the pool range -- it belongs to
	 * something else and may not be mapped in hyp_vmemmap.
	 */
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;

	return sekvm_phys_to_page(addr);
}

/* Find a buddy page currently available for allocation */
static struct hyp_page *__find_buddy_avail(struct hyp_pool *pool,
					   struct hyp_page *p,
					   unsigned short order)
{
	struct hyp_page *buddy = __find_buddy_nocheck(pool, p, order);

	if (!buddy || buddy->order != order || buddy->refcount)
		return NULL;

	return buddy;

}

/*
 * Pages that are available for allocation are tracked in free-lists, so we use
 * the pages themselves to store the list nodes to avoid wasting space. As the
 * allocator always returns zeroed pages (which are zeroed on the hyp_put_page()
 * path to optimize allocation speed), we also need to clean-up the list node in
 * each page when we take it out of the list.
 */
static inline void page_remove_from_list(struct hyp_page *p)
{
	struct list_head *node = sekvm_page_to_virt(p);

	__list_del_entry(node);
	memset(node, 0, sizeof(*node));
}

static inline void page_add_to_list(struct hyp_page *p, struct list_head *head)
{
	struct list_head *node = sekvm_page_to_virt(p);

	INIT_LIST_HEAD(node);
	list_add_tail(node, head);
}

static inline struct hyp_page *node_to_page(struct list_head *node)
{
	return sekvm_virt_to_page(node);
}

static void __hyp_attach_page(struct hyp_pool *pool,
			      struct hyp_page *p, bool init)
{
	unsigned short order = p->order;
	struct hyp_page *buddy;

	if (init)
		memset(sekvm_page_to_virt(p), 0, PAGE_SIZE << p->order);

	/*
	 * Only the first struct hyp_page of a high-order page (otherwise known
	 * as the 'head') should have p->order set. The non-head pages should
	 * have p->order = HYP_NO_ORDER. Here @p may no longer be the head
	 * after coallescing, so make sure to mark it HYP_NO_ORDER proactively.
	 */
	p->order = HYP_NO_ORDER;
	for (; (order + 1) < pool->max_order; order++) {
		buddy = __find_buddy_avail(pool, p, order);
		if (!buddy)
			break;

		/* Take the buddy out of its list, and coallesce with @p */
		page_remove_from_list(buddy);
		buddy->order = HYP_NO_ORDER;
		p = min(p, buddy);
	}

	/* Mark the new head, and insert it */
	p->order = order;
	page_add_to_list(p, &pool->free_area[order]);
}

static struct hyp_page *__hyp_extract_page(struct hyp_pool *pool,
					   struct hyp_page *p,
					   unsigned short order)
{
	struct hyp_page *buddy;

	page_remove_from_list(p);
	while (p->order > order) {
		/*
		 * The buddy of order n - 1 currently has HYP_NO_ORDER as it
		 * is covered by a higher-level page (whose head is @p). Use
		 * __find_buddy_nocheck() to find it and inject it in the
		 * free_list[n - 1], effectively splitting @p in half.
		 */
		p->order--;
		buddy = __find_buddy_nocheck(pool, p, p->order);
		buddy->order = p->order;
		page_add_to_list(buddy, &pool->free_area[buddy->order]);
	}

	return p;
}

static inline void hyp_page_ref_inc(struct hyp_page *p)
{
	BUG_ON(p->refcount == USHRT_MAX);
	p->refcount++;
}

static inline int hyp_page_ref_dec_and_test(struct hyp_page *p)
{
	BUG_ON(!p->refcount);
	p->refcount--;
	return (p->refcount == 0);
}

static inline void hyp_set_page_refcounted(struct hyp_page *p)
{
	BUG_ON(p->refcount);
	p->refcount = 1;
}

static void __hyp_put_page(struct hyp_pool *pool, struct hyp_page *p, bool init)
{
	if (hyp_page_ref_dec_and_test(p))
		__hyp_attach_page(pool, p, init);
}

/*
 * Changes to the buddy tree and page refcounts must be done with the hyp_pool
 * lock held. If a refcount change requires an update to the buddy tree (e.g.
 * hyp_put_page()), both operations must be done within the same critical
 * section to guarantee transient states (e.g. a page with null refcount but
 * not yet attached to a free list) can't be observed by well-behaved readers.
 */
void host_put_page(struct hyp_pool *pool, void *addr)
{
	struct hyp_page *p = sekvm_virt_to_page(addr);

	spin_lock(&pool->lock);
	__hyp_put_page(pool, p, 0);
	spin_unlock(&pool->lock);
}

void host_get_page(struct hyp_pool *pool, void *addr)
{
	struct hyp_page *p = sekvm_virt_to_page(addr);

	spin_lock(&pool->lock);
	hyp_page_ref_inc(p);
	spin_unlock(&pool->lock);
}

void host_split_page(struct hyp_page *p)
{
	unsigned short order = p->order;
	unsigned int i;

	p->order = 0;
	for (i = 1; i < (1 << order); i++) {
		struct hyp_page *tail = p + i;

		tail->order = 0;
		hyp_set_page_refcounted(tail);
	}
}

static void host_free_pages(struct hyp_pool *pool, void *addr)
{
	struct hyp_page *p;

	spin_lock(&pool->lock);
	p = sekvm_virt_to_page(addr);
	__hyp_put_page(pool, p, 0);
	spin_unlock(&pool->lock);
	return;
}

static void *host_alloc_pages(struct hyp_pool *pool, unsigned short order)
{
	unsigned short i = order;
	struct hyp_page *p;
	spin_lock(&pool->lock);

	/* Look for a high-enough-order page */
	while (i < pool->max_order && list_empty(&pool->free_area[i]))
		i++;
	if (i >= pool->max_order) {
		spin_unlock(&pool->lock);
		return NULL;
	}

	/* Extract it from the tree at the right order */
	p = node_to_page(pool->free_area[i].next);
	p = __hyp_extract_page(pool, p, order);

	hyp_set_page_refcounted(p);
	spin_unlock(&pool->lock);

	return sekvm_page_to_virt(p);
}

void *host_alloc_pt_pages(unsigned short order)
{
	if (!host_s1_sparse_mem_base)
		return NULL;
	else
		return host_alloc_pages(&host_s1_pgtable_pool, order);
}

void host_free_pt_pages(unsigned long addr)
{
	host_free_pages(&host_s1_pgtable_pool, addr);
}

void *host_alloc_mod_pages(unsigned short order, bool ro)
{
	if (ro)
		return host_alloc_pages(&host_s1_module_ro_pool, order);
	else
		return host_alloc_pages(&host_s1_module_text_pool, order);
}

int host_s1_pool_init(struct hyp_pool* pool, u64 base, u64 size)
{
	struct hyp_page *p;
	int i;
	unsigned int nr_pages = size >> PAGE_SHIFT;
	phys_addr_t phys = base;

	u64 pfn = phys >> PAGE_SHIFT;
	spin_lock_init(&pool->lock);
	pool->max_order = min(MAX_ORDER, get_order(nr_pages << PAGE_SHIFT));
	for (i = 0; i < pool->max_order; i++)
		INIT_LIST_HEAD(&pool->free_area[i]);
	pool->range_start = phys;
	pool->range_end = phys + (nr_pages << PAGE_SHIFT);

	p = sekvm_phys_to_page(phys);
	for (i = 0; i < nr_pages; i++) {
		p[i].order = 0;
		hyp_set_page_refcounted(&p[i]);
	}

	/* Attach the unused pages to the buddy tree */
	for (i = 0; i < nr_pages; i++)
		__hyp_put_page(pool, &p[i], 1);

	return 0;
}

void host_s1_pool_finalise(void)
{
		if (host_s1_sparse_mem_base)
			host_s1_pool_init(&host_s1_pgtable_pool,
							host_s1_sparse_mem_base, host_s1_sparse_mem_size);
		host_s1_pool_init(&host_s1_module_ro_pool,
						host_s1_module_ro_base, host_s1_module_ro_size);
		host_s1_pool_init(&host_s1_module_text_pool,
						host_s1_module_text_base, host_s1_module_text_size);
}

void __init sekvm_divide_reserve_mem(void)
{	
		BUG_ON(!host_s1_pgtable_early_mem_base ||
						host_s1_pgtable_early_mem_base < host_s1_pgtable_mem_base);

		u64 rest = host_s1_pgtable_early_mem_base - host_s1_pgtable_mem_base;

		if (rest < PMD_SIZE)
		{
				host_s1_sparse_mem_base = 0UL;
		}
		else
		{
			host_s1_sparse_mem_base = host_s1_pgtable_mem_base;
			host_s1_sparse_mem_size = ALIGN(host_s1_pgtable_early_mem_base - PMD_SIZE, PMD_SIZE)
					- host_s1_sparse_mem_base;
	
			BUG_ON(!host_s1_sparse_mem_base || host_s1_sparse_mem_size < 0);
		
			pr_info("SeKVM: Sparse memory : %llx - %llx\n",
							host_s1_sparse_mem_base,
							host_s1_sparse_mem_base + host_s1_sparse_mem_size);
		}

		/*
		 * The part of kernel module
		 * +-------------+------+-----------------+----+-------------+
		 * | unused page | text | 2 * unused page | ro | unused page |
		 * +-------------+------+-----------------+----+-------------+
		 */

		u64 mod_pages = host_s1_module_pages();

		BUG_ON((host_s1_mem_base + (mod_pages << PAGE_SHIFT))
						> host_s1_pgtable_mem_base);
		
		host_s1_module_text_base = host_s1_mem_base + PAGE_SIZE;
		host_s1_module_text_size = ((mod_pages / 2) << PAGE_SHIFT) - (2 * PAGE_SIZE);

		host_s1_module_ro_base = ALIGN(host_s1_module_text_base + host_s1_module_text_size,
						PMD_SIZE) + PAGE_SIZE;
		host_s1_module_ro_size = ((mod_pages / 2) << PAGE_SHIFT) - (2 * PAGE_SIZE);

		BUG_ON(!host_s1_module_text_base || !host_s1_module_ro_base);

		pr_info("SeKVM: Module memory:\n"
				"\ttext  : %llx - %llx\n"
				"\tro    : %llx - %llx\n",
				host_s1_module_text_base, host_s1_module_text_base + host_s1_module_text_size,
				host_s1_module_ro_base, host_s1_module_ro_base + host_s1_module_ro_size);


		u64 vm_size = host_s1_vmemmap_pages(sizeof(struct hyp_page));
		__sekvm_vmemmap = __va(memblock_alloc(vm_size, PMD_SIZE));

		pr_info("SeKVM: Reserved %lld B at 0x%llx - vmemmap\n", vm_size,
						__sekvm_vmemmap);

		/* Almost done, clear early mem base */
		host_s1_pgtable_early_mem_base = 0;

		host_s1_pool_finalise();
	}

void __init early_sekvm_hyp_reserve(void)
{
	/*
	 * FIXME: hardcode the value for now.
	 * 1. Stage 1 kernel page table (256 + 128) * 2MB
	 * 2. Stage 1 kernel module (RO) 64 * 2MB
	 * 3. Stage 1 kernel module (TEXT) 64 * 2MB
	 * +-------------------+-----------------+----------+
	 * | host module(text) | host module(ro) | host kpt |
	 * +-------------------+-----------------+----------+
	 */
	unsigned long total_pages = 0UL;

	total_pages += host_s1_pgtable_pages();
	total_pages += host_s1_module_pages();

	host_s1_mem_size = total_pages << PAGE_SHIFT;

	/*
	 * Since in the stage 2 translation page table, the host user and
	 * kernel will share the same stage 2 page table (vttbr_el2).
	 *
	 * Here, we hope to allocate PMD-aligned pages for kernel pages
	 * and PUD-aligned pages for user pages in stage 2 translation to
	 * reduce TLB pressure and separate both at different PUD block.
	 */
	host_s1_mem_base = memblock_alloc(ALIGN(host_s1_mem_size, PUD_SIZE),
					PUD_SIZE);

	if (!host_s1_mem_base)
		host_s1_mem_base = memblock_alloc(ALIGN(host_s1_mem_size, PMD_SIZE),
						PMD_SIZE);
	else
		host_s1_mem_size = ALIGN(host_s1_mem_size, PUD_SIZE);

	if (!host_s1_mem_base)
		host_s1_mem_base = memblock_alloc(host_s1_mem_size, PAGE_SIZE);
	else
		host_s1_mem_size = ALIGN(host_s1_mem_size, PMD_SIZE);

	/* OOM, not handled from now.*/
	BUG_ON(!host_s1_mem_base);

	/*
	 * Reserve two reserved pages/block to safely bind
	 * both sides of the kernel page table pool
	 * +------------------+---------------+----------------+------------------+
	 * | unused 2MB block | host rest kpt | host early kpt | unused 2MB block |
	 * +------------------+---------------+----------------+------------------+
	 */
	host_s1_pgtable_mem_base = host_s1_mem_base
			+ (host_s1_module_pages() << PAGE_SHIFT) + PMD_SIZE;
	host_s1_pgtable_mem_size = (host_s1_pgtable_pages() << PAGE_SHIFT) - (2 * PMD_SIZE);
	host_s1_pgtable_early_mem_base = host_s1_pgtable_mem_base + host_s1_pgtable_mem_size;

	pr_info("SeKVM: Reserved %lld MiB at 0x%llx\n", host_s1_mem_size  >> 20,
					host_s1_mem_base);
}
