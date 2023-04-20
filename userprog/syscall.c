#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/mmu.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
tid_t fork (const char *thread_name, struct intr_frame *if_);
int exec (const char *file);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	/* Initialize file_system_lock */
	lock_init(&file_system_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	switch(f->R.rax) {
		case SYS_HALT : {
			halt();
			break;
		}

		case SYS_EXIT : {
			exit(f->R.rdi);
			break;
		}

		case SYS_FORK : {
			f->R.rax = fork(f->R.rdi, f);
			break;
		}


		case SYS_EXEC : {
			f->R.rax = exec(f->R.rdi);
			break;
		}

		case SYS_WAIT : {
			f->R.rax = wait(f->R.rdi);
			break;
		}

		case SYS_CREATE : {
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		}

		case SYS_REMOVE : {
			f->R.rax = remove(f->R.rdi);
			break;
		}

		case SYS_OPEN : {
			f->R.rax = open(f->R.rdi);
			break;
		}

		case SYS_FILESIZE : {
			f->R.rax = filesize(f->R.rdi);
			break;
		}

		case SYS_READ : {
			f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
			break;
		}

		case SYS_WRITE : {
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		}

		case SYS_SEEK : {
			seek(f->R.rdi, f->R.rsi);
			break;
		}

		case SYS_TELL : {
			f->R.rax = tell(f->R.rdi);
			break;
		}

		case SYS_CLOSE : {
			close(f->R.rdi);
			break;
		}

		default:
			exit(-1);
	}
}

void 
check_address(void *addr) {
	struct thread *t = thread_current();

	/* Check if the address is valid
	1) Check if the address is user virtual address
	2) Check if the address is NULL
	3) Check if the address is mapped to a page */
	if ((is_user_vaddr(addr) == false) || (addr == NULL) || (pml4_get_page (t->pml4, addr) == NULL))
		exit(-1);
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *cur = thread_current();
	cur->exit_status=status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit(); 
}


tid_t fork (const char *thread_name, struct intr_frame *if_) {
	return process_fork(thread_name, if_);
}

int exec (const char *file) {
	char *fn_copy;
	
	check_address(file);

	// Copy the file name
	fn_copy = palloc_get_page(PAL_USER);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file, PGSIZE);

	// Execute the file
	int result = process_exec(fn_copy);
	palloc_free_page(fn_copy);
	return result;
}

int wait (tid_t pid) {
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
	check_address(file);
	bool success = filesys_create(file, initial_size);
	return success;
}

bool remove (const char *file) {
	check_address(file);
	bool success = filesys_remove(file);
	return success;
}

int open(const char *file) {
	struct thread *cur = thread_current();

	check_address(file);

	if (lock_held_by_current_thread(&file_system_lock))
		return -1;
	
	while (cur->fd_table[cur->fd_idx] && cur->fd_idx < FDCOUNT_LIMIT) {
		cur->fd_idx++;
	}
	
	if (cur->fd_idx >= FDCOUNT_LIMIT)
		return -1;
	
	lock_acquire(&file_system_lock);
	
	struct file *open_file = filesys_open(file);
	if (open_file == NULL)
		return -1;

	cur->fd_table[cur->fd_idx] = open_file;

	lock_release(&file_system_lock);

	return cur->fd_idx;
}


int filesize (int fd) {
	int file_len;
	struct file * temp;

	temp = retrieve_process_file(fd);

	if (temp == NULL)
		return -1;

	file_len = file_length(temp);

	return file_len;
}


int read (int fd, void* buffer, unsigned size) {
	struct file * file_;
	off_t file_byte;

	// Check if the address to read is valid (buffer ~ buffer + size)
	check_address(buffer);
	check_address(buffer + size-1);

	file_ = retrieve_process_file(fd);

	
	if (fd == 1 || fd < 0) { // if fd is 1 or negative, return -1 (error)
		return -1;
	} else if (fd == 0) { // if fd is 0, read from keyboard
		lock_acquire(&file_system_lock);

		if (size == 0)
			return 0;

		int buffer_size;
		for (buffer_size = 0; buffer_size < size; buffer_size++) {
			*(uint8_t*)buffer = input_getc(); // read from keyboard
			buffer++; // move to next byte
		}

		lock_release(&file_system_lock);
		return buffer_size;
	} else {
		lock_acquire(&file_system_lock);

		if (file_ == NULL){
			lock_release(&file_system_lock);
			return 0;
		}

		else {
			file_byte = file_read(file_, buffer, size);
			if (file_byte == 0) {
				lock_release(&file_system_lock);
				return 0;
			} 

			lock_release(&file_system_lock);
			return file_byte;
		}
	}
}

int write(int fd, const void *buffer, unsigned size) {	
	struct file * temp;
	off_t file_byte;

	// Check if the address to write is valid (buffer ~ buffer + size)
	check_address(buffer);
	check_address(buffer + size - 1);

	temp = retrieve_process_file(fd);
	
	if (fd < 0) { // if fd is negative, return -1 (error)
		return -1;
	} else if (fd == 1) { // if fd is 1, write to console
		putbuf(buffer, size);	
		return size;
	} else if (fd == 0) { // if fd is 0, return 0
		return 0;
	} else if (temp == NULL) { // if file is not opened, return 0
		return 0;
	} else { // if file is opened, write to file
		lock_acquire(&file_system_lock);
		file_byte = file_write(temp,buffer,size);
		if (file_byte == 0){
			lock_release(&file_system_lock);
			return 0;
		}

		lock_release(&file_system_lock);
		return file_byte;
	}
}


void seek (int fd, unsigned position) {
	file_seek(retrieve_process_file(fd), position);
}


unsigned tell (int fd) {
	struct file * file_;
	file_ = retrieve_process_file(fd);
	return file_tell(file_) ? file_tell(file_) : -1;
}

void close (int fd) {
	struct file * file_;
	struct thread *cur = thread_current();
	
	if (fd < 0)
		return;

	file_ = retrieve_process_file(fd);

	lock_acquire(&file_system_lock);
	file_close(file_);

	cur->fd_table[fd] = 0;
	lock_release(&file_system_lock);
}

