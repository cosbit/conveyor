# Conveyor

A Nix-native, two-port transparent Ethernet bridge using TC eBPF. Frames arriving
on `eth0` are forwarded to `eth1`, and frames arriving on `eth1` are forwarded to
`eth0`. Each ingress frame is also cloned to a virtual capture interface,
`conveyor0`. Forwarding and mirroring stay in the kernel; the daemon only manages
setup and teardown.

```text
upstream network --- eth0  <--- TC eBPF --->  eth1 --- downstream network
                                 |
                            cloned frame
                                 v
                       internal veth --> conveyor0 --> tcpdump / AF_PACKET
```

This is an inline Ethernet wire, with no MAC learning, routing, NAT, IP address,
STP, or Linux bridge device. Broadcasts, multicast, unknown unicast, and VLAN
frames follow the same path. The observer is a veth endpoint rather than a
Linux `bridge` interface: multiple applications can independently subscribe using
libpcap or `AF_PACKET`, including frames whose destination MAC is not the observer's.
The observer combines both directions and does not encode direction metadata.
Sending on the observer does not inject traffic into either physical port.

## Build and run

```sh
nix build path:.
sudo ./result/bin/conveyor eth0 eth1
# In another terminal (tcpdump must be installed):
sudo tcpdump -eni conveyor0
```

Arguments: `conveyor UPSTREAM DOWNSTREAM [OBSERVER]`; default observer:
`conveyor0`. Both ports must already be up, have equal MTUs, and be dedicated to
Conveyor. Remove their IP addresses, DHCP, IPv6 autoconfiguration, bridge/bond
membership, and other traffic control filters before use. Manage the host over a
separate interface. The daemon refuses existing observer names and acquires
promiscuous packet-socket memberships on both ports, releasing them on exit.
It does not change port addresses, MTUs, or administrative state.

Root with BPF and network administration privileges is required. Linux must
support BPF, TC classifier/action hooks, and veth. The build supports x86_64 and
aarch64 Linux. SIGTERM / Ctrl-C detaches Conveyor's filters and deletes its veth
pair. An abrupt SIGKILL leaves filters and veth devices behind; recover with:

```sh
sudo tc filter del dev eth0 ingress pref 1 handle 0xc0 bpf
sudo tc filter del dev eth1 ingress pref 1 handle 0xc0 bpf
sudo ip link del conveyor0
```

Conveyor reserves ingress priority 1, handle `0xc0`, and refuses to replace a
filter at that position. Empty clsact qdiscs are deliberately retained after exit
to avoid deleting filters owned by other applications.

## NixOS

Import this flake's module and configure dedicated ports:

```nix
{
  imports = [ inputs.conveyor.nixosModules.default ];
  services.conveyor = {
    enable = true;
    upstream = "eth0";
    downstream = "eth1";
    observer = "conveyor0";
  };
}
```

The module disables DHCP on those ports, brings them up before starting the
daemon, and restarts it on failure. Configure the host's network manager to leave
these ports unnumbered, including IPv6. Do not enable another bridge or DHCP client
on them. Stop the service before changing port names or their MTUs.

## Development and tests

```sh
nix develop path:.
make
sudo python3 tests/integration.py --binary "$PWD/build/conveyor"
# Or run everything in an isolated NixOS VM, without host root:
nix build 'path:.#checks.x86_64-linux.integration' -L
```

The integration suite creates two veth port pairs in a disposable network
namespace, sends synthetic Ethernet packets from both sides, and checks:

- Byte-for-byte forwarding and tapping of unicast, broadcast, multicast, VLAN,
  and full-MTU frames, with no reflection or duplicate mirror delivery.
- Independent capture by multiple observer applications.
- Observer transmission isolation from the two bridge ports.
- Rejection of an existing observer, clean shutdown, preservation of an existing
  clsact qdisc, release of promiscuous memberships, and successful restart.

The VM test uses the packaged binary and real kernel eBPF verifier, TC hooks,
and networking. It is not a userspace simulation. VM execution requires KVM or
Nix's supported VM test execution environment.

## Performance and limits

TC is used because it can both clone full frames to an ordinary capture device
and redirect originals. The hot path performs one configuration-map lookup,
one clone/redirect, and one redirect. See the upstream kernel's documentation of
[`bpf_clone_redirect` and `bpf_redirect`](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/ea5751ccd665a2fd1b24f9af81f6167f0718c5f6/tools/include/uapi/linux/bpf.h).
Mirroring has an unavoidable clone and veth receive cost; no throughput or latency
target has yet been benchmarked.

Forwarding continues if the mirror helper fails or a capture application's socket
drops packets. Capture is best effort; there is no backpressure or lossless
capture guarantee. TC observes kernel packet buffers: NIC offloads can coalesce
packets, strip VLAN tags into metadata, or defer checksum work. Disable GRO/LRO,
GSO/TSO, and VLAN offloads on the dedicated ports when exact on-wire capture
fidelity is needed. Hardware-specific offload behavior is outside the veth tests.
Raw `AF_PACKET` readers should enable `PACKET_AUXDATA` and reconstruct VLAN
headers from that metadata; libpcap handles this for capture applications.

There is no loop prevention, fail-open bypass, or automatic link-failure handling.
The port filters become active sequentially during startup and are removed
sequentially during shutdown; setup is not atomic. Detaching them stops inline
forwarding. Only ingress traffic is bridged; local host traffic sent directly
through the physical ports is outside the bridge path. Observers see original
Ethernet payloads and should be treated as privileged network access.
