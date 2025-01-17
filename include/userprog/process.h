#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

struct file *retrieve_process_file(int fd);
struct thread *retrieve_child_thread(int pid);
void remove_child_thread(struct thread *child_process);

struct file_info
{
	struct file *file;
	off_t ofs;
	uint32_t page_read_bytes;
	uint32_t page_zero_bytes;
};

#endif /* userprog/process.h */
