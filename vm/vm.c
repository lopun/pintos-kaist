/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *new_page = palloc_get_page(PAL_USER);

		if (VM_TYPE(type) == VM_ANON)
		{
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE)
		{
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		}

		/* TODO: Insert the page into the spt. */
		new_page->rw = writable;

		return spt_insert_page(spt, new_page);
	}

	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page pg;
	pg.va = pg_round_down(va);

	struct hash_elem *elem = hash_find(&spt->spt_hash, &pg.hash_elem);
	if (elem == NULL)
		return NULL;

	return hash_entry(elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;

	struct hash_elem *elem = hash_insert(&spt->spt_hash, &page->hash_elem);

	if (elem == NULL)
		succ = true;

	return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	if (hash_delete(&spt->spt_hash, &page->hash_elem))
	{
		vm_dealloc_page(page);
	}
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	struct thread *curr = thread_current();

	// struct hash hash = curr->spt->spt_hash;
	// struct hash_iterator *iter;
	// hash_first(iter, &hash);
	// while (hash_next(iter))
	// {

	// 	struct page *cur_page = hash_entry(iter->elem, struct page, hash_elem);

	// 	if (pml4_is_accessed(curr->pml4, cur_page->va))
	// 	{
	// 		pml4_set_accessed(curr->pml4, cur_page->va, false);
	// 		continue;
	// 	}
	// 	if (cur_page->frame == NULL)
	// 		continue;

	// 	if (page_get_type(cur_page) == VM_FILE)
	// 	{
	// 		victim = cur_page->frame;
	// 		break;
	// 	}
	// 	else if (page_get_type(cur_page) == VM_ANON)
	// 	{
	// 		victim = cur_page->frame;
	// 		break;
	// 	}
	// }

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	if (victim != NULL)
	{
		struct thread *curr = thread_current();
		struct page *victim_page = victim->page;

		swap_out(victim_page);
	}

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);
	frame->page = NULL;

	if (!frame->kva)
	{
		frame = NULL;
		PANIC("TODO: swap out");
	}

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	if (spt_find_page(&thread_current()->spt, addr))
	{
		return;
	}

	uintptr_t stack_btm = pg_round_down(addr);
	vm_alloc_page(VM_ANON, stack_btm, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	bool success;

	if (is_kernel_vaddr(addr) || addr == NULL)
	{
		return false;
	}

	uintptr_t stack_limit = USER_STACK - (1 << 20);
	uintptr_t rsp = user ? f->rsp : thread_current()->user_rsp;

	if (addr <= USER_STACK && addr >= stack_limit && addr >= rsp - 8)
	{
		vm_stack_growth(addr);
	}
	struct page *_page = spt_find_page(spt, addr);
	if (_page == NULL)
		return false;

	return vm_do_claim_page(_page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	if (frame == NULL)
	{
		frame = vm_evict_frame();
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *curr = thread_current();

	if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->rw))
		return false;

	return swap_in(page, frame->kva);
}

/* Returns a hash value for page. */
unsigned page_hash_val(const struct hash_elem *elem, void *aux UNUSED)
{
	const struct page *pg = hash_entry(elem, struct page, hash_elem);
	return hash_bytes(&pg->va, sizeof pg->va);
}

/* deallocate page */
void page_dealloc(struct hash_elem *elem, void *aux)
{
	struct page *pg = hash_entry(elem, struct page, hash_elem);
	vm_dealloc_page(pg);
}

/* Returns true if page a hash_elem address < b hash_elem address. */
bool page_va_compare(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash, page_hash_val, page_va_compare, NULL);
}

/* 보조 테이블 src를 dst로 복사 */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED)
{
	struct hash_iterator i;
	struct hash *parent_hash = &src->spt_hash;

	/* for i in src */
	hash_first(&i, parent_hash);
	while (hash_next(&i))
	{
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);

		if (parent_page->operations->type == VM_UNINIT)
		{
			vm_initializer *init = parent_page->uninit.init;
			void *aux = parent_page->uninit.aux;

			vm_alloc_page_with_initializer(parent_page->uninit.type, parent_page->va, parent_page->rw, init, aux);
		}
		else
		{
			vm_alloc_page(page_get_type(parent_page), parent_page->va, parent_page->rw);
			vm_claim_page(parent_page->va);

			struct page *child_page = spt_find_page(dst, parent_page->va);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct hash_iterator i;
	struct hash *parent_hash = &spt->spt_hash;

	if (parent_hash == NULL)
	{
		return;
	}

	hash_first(&i, parent_hash);
	while (hash_next(&i))
	{
		struct page *page_to_be_destroyed = hash_entry(hash_cur(&i), struct page, hash_elem);
		destroy(page_to_be_destroyed);
		hash_delete(parent_hash, hash_cur(&i));
	}
}