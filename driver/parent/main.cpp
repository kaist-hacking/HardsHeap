#include <assert.h>
#include <dlfcn.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "shared_memory.h"
#include "api.h"
#include "common/stream.h"
#include "common/utils.h"

SharedMemory g_shm;
Stream       g_shm_strm;
// TODO: make this configurable
static int    n_runs = 100;
double threshold = 0.25;
int dev_null_fd = -1;
pid_t child_pid = 0;

#define MAX_ARGC 256
char* module_args = NULL;
char* child_args = NULL;
char* input_file = NULL;
char* bitmap_file = NULL;

void handler(int signum)
{
    if (child_pid) kill(child_pid, SIGKILL);
    exit(0);
}

int exec(bool verbose, char* path, char** argv)
{
    child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (!child_pid) {
        // child
        if (!verbose) {
            dup2(dev_null_fd, 1);
            dup2(dev_null_fd, 2);
        }
        if (execv(path, (char**)argv) == -1) {
            perror("execve");
            exit(EXIT_FAILURE);
        }
        return -1;
    } else {
        // parent
        int wstatus = 0;
        if (waitpid(child_pid, &wstatus, 0) == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
        child_pid = 0;
        return wstatus;
    }
}

char* find_child(char* argv0)
{
    fs::path cur = fs::absolute(argv0);
    fs::path child = cur.parent_path().append("child");
    assert(fs::exists(child));

    return strdup(child.c_str());
}

void open_dev_null()
{
    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd == -1) {
        fprintf(stderr, "Failed to open /dev/null\n");
        exit(EXIT_FAILURE);
    }
}

bool do_debug() {
    return getenv("DEBUG") != NULL;
}

void usage(char* argv0) {
  fprintf(stderr,
  "Usage: %s [OPTION] ... FILE [MAPFILE]\n"
  "  -n <n_runs>: Set the number of runs\n"
  "  -t <threshold>: Set threshold for reporting\n"
  "  -c <child_args>: Set an argument string for a child\n"
  "  -m <module_args>: Set an argument string for a specific module\n"
  "  -h: Display this help and exit\n", argv0);
}

void parse_args(int argc, char** argv)
{
    char c = 0;
    while ((c = getopt(argc, argv, "n:t:c:m:h:")) != -1) {
        switch (c) {
        case 'n':
            n_runs = strtoul(optarg, NULL, 10);
            break;
        case 't':
            threshold = strtod(optarg, NULL);
            break;
        case 'c':
            child_args = optarg;
            break;
        case 'm':
            module_args = optarg;
            break;
        case 'h':
        default: {
            usage(argv[0]);
            exit(-1);
        }
        }
    }

    // WARNING: Repeated code from child
    if (argc == optind || argc > optind + 2) {
        usage(argv[0]);
        exit(-1);
    }

    input_file = argv[optind];
    if (argc == optind + 2)
        bitmap_file = argv[optind + 1];
}

int string_to_child_argv(char* args, char* argv0, char** argv, int size) {
    // Will append two more arguments in argv
    const int max_additional_args = 5;
    int argc = string_to_argv(args, argv0, argv, size - max_additional_args);
    if (module_args != NULL) {
        // XXX: A bad way to make a string literal to char*.
        // This will lead memory leak.
        argv[argc++] = strdup("-m");
        argv[argc++] = module_args;
    }
    argv[argc++] = input_file;
    if (bitmap_file != NULL)
        argv[argc++] = bitmap_file;
    argv[argc] = NULL;
    return argc;
}

void cleanup() {
  shm_fini(&g_shm);
}

int main(int argc, char** argv)
{
    char* child = find_child(argv[0]);
    parse_args(argc, argv);

    char* child_argv[MAX_ARGC];
    int child_argc = string_to_child_argv(child_args, child, child_argv, MAX_ARGC);

    shm_alloc(&g_shm);
    atexit(cleanup);

    stream_init(&g_shm_strm, g_shm.ptr, g_shm.length);
    open_dev_null();

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;

    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    if (getenv("HARDSHEAP_PRELOAD")) {
        setenv("LD_PRELOAD", getenv("HARDSHEAP_PRELOAD"), 1);
        setenv("DYLD_INSERT_LIBRARIES", getenv("HARDSHEAP_PRELOAD"), 1);
    }

    initialize();

    for (int i = 0; i < n_runs; i++) {
        stream_clear(&g_shm_strm);
        exec(do_debug(), child, child_argv);
        analyze_single();
    }

    double prob = calculate_prob();

    stream_clear(&g_shm_strm);
    exec(true, child, child_argv);

    finalize();
    close(dev_null_fd);

    fprintf(stderr, "// [INFO] Probability: %lf\n", prob);
    shm_fini(&g_shm);

    if (prob > threshold) {
        kill(getpid(), SIGUSR2);
    }

    return 0;
}
