#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bridge.h"

#ifndef BPF_OBJECT
#define BPF_OBJECT "build/bridge.bpf.o"
#endif
#ifndef IP_COMMAND
#define IP_COMMAND "ip"
#endif

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

static int ip(char *const args[])
{
    pid_t child = fork();
    if (child < 0) return -errno;
    if (!child) { execvp(IP_COMMAND, args); perror(IP_COMMAND); _exit(127); }
    int status;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR) return -errno;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

static int promiscuous(unsigned index)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    struct packet_mreq req = { .mr_ifindex = (int)index, .mr_type = PACKET_MR_PROMISC };
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &req, sizeof(req))) {
        int err = -errno; close(fd); return err;
    }
    return fd;
}

static int mtu(const char *name)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", name);
    FILE *f = fopen(path, "r");
    int value = 0;
    if (f) { if (fscanf(f, "%d", &value) != 1) value = 0; fclose(f); }
    return value;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        puts("Usage: conveyor UPSTREAM DOWNSTREAM [OBSERVER]\n"
             "Ports must be UP, have equal MTUs, and be dedicated to conveyor.\n"
             "OBSERVER defaults to conveyor0; requires root / network and BPF privileges.");
        return 0;
    }
    if (argc < 3 || argc > 4) { fprintf(stderr, "Usage: conveyor UPSTREAM DOWNSTREAM [OBSERVER]\n"); return 2; }
    const char *observer = argc == 4 ? argv[3] : "conveyor0";
    char internal[IFNAMSIZ];
    snprintf(internal, sizeof(internal), "cv%u", (unsigned)getpid());
    struct bridge_config cfg = { .upstream = if_nametoindex(argv[1]), .downstream = if_nametoindex(argv[2]) };
    if (!cfg.upstream || !cfg.downstream || cfg.upstream == cfg.downstream ||
        strlen(observer) >= IFNAMSIZ || !observer[0] || if_nametoindex(observer) ||
        if_nametoindex(internal) || !strcmp(internal, observer) ||
        mtu(argv[1]) <= 0 || mtu(argv[1]) != mtu(argv[2])) {
        fprintf(stderr, "Invalid ports, unequal MTUs, or observer name already in use\n"); return 2;
    }
    /* Block termination during setup; sigwait below also avoids pause races. */
    sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals, SIGINT); sigaddset(&signals, SIGTERM);
    sigprocmask(SIG_BLOCK, &signals, NULL);
    signal(SIGINT, stop); signal(SIGTERM, stop);
    struct bpf_object *obj = NULL;
    struct bpf_tc_hook hooks[2] = {
        { .sz = sizeof(struct bpf_tc_hook), .ifindex = cfg.upstream, .attach_point = BPF_TC_INGRESS },
        { .sz = sizeof(struct bpf_tc_hook), .ifindex = cfg.downstream, .attach_point = BPF_TC_INGRESS }
    };
    struct bpf_tc_opts opts = { .sz = sizeof(opts), .handle = 0xc0, .priority = 1 };
    bool attached[2] = {false, false}, pair = false;
    int sockets[2] = {-1, -1}, err = 0;
    char size[16]; snprintf(size, sizeof(size), "%d", mtu(argv[1]));
    char *add[] = { "ip", "link", "add", internal, "mtu", size, "type", "veth", "peer", "name", (char *)observer, "mtu", size, NULL };
    if ((err = ip(add))) goto out;
    pair = true;
    char *up1[] = { "ip", "link", "set", "dev", internal, "up", NULL };
    char *up2[] = { "ip", "link", "set", "dev", (char *)observer, "up", NULL };
    if ((err = ip(up1)) || (err = ip(up2))) goto out;
    cfg.mirror = if_nametoindex(internal);
    for (int i = 0; i < 2; i++) {
        sockets[i] = promiscuous(hooks[i].ifindex);
        if (sockets[i] < 0) { err = sockets[i]; goto out; }
    }
    obj = bpf_object__open_file(BPF_OBJECT, NULL);
    err = libbpf_get_error(obj);
    if (err) { obj = NULL; goto out; }
    if ((err = bpf_object__load(obj))) goto out;
    int map = bpf_object__find_map_fd_by_name(obj, "config");
    __u32 key = 0;
    if (bpf_map_update_elem(map, &key, &cfg, BPF_ANY)) { err = -errno; goto out; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "conveyor_forward");
    if (!prog) { err = -ENOENT; goto out; }
    opts.prog_fd = bpf_program__fd(prog);
    for (int i = 0; i < 2; i++) {
        err = bpf_tc_hook_create(&hooks[i]);
        if (err && err != -EEXIST) goto out;
        /* attach writes prog_id back; the next call requires it to be zero. */
        opts.prog_id = 0;
        if ((err = bpf_tc_attach(&hooks[i], &opts))) goto out;
        attached[i] = true;
    }
    printf("ready: %s <-> %s; observer %s\n", argv[1], argv[2], observer);
    fflush(stdout);
    while (!stopping) {
        int sig;
        int result = sigwait(&signals, &sig);
        if (result) { err = -result; break; }
        stopping = 1;
    }
out:
    if (err) fprintf(stderr, "conveyor: %s (%d)\n", strerror(-err), err);
    for (int i = 1; i >= 0; i--) {
        struct bpf_tc_opts detach = { .sz = sizeof(detach), .handle = opts.handle, .priority = opts.priority };
        if (attached[i]) bpf_tc_detach(&hooks[i], &detach);
        if (sockets[i] >= 0) close(sockets[i]);
    }
    bpf_object__close(obj);
    if (pair) {
        char *del[] = { "ip", "link", "del", internal, NULL };
        ip(del);
    }
    return err ? 1 : 0;
}
