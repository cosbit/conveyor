#!/usr/bin/env python3
"""Root-only integration suite; all topology changes live in a disposable netns."""
import argparse
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stdout}{result.stderr}')
    return result


def packet_socket(name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((name, 0))
    s.setsockopt(263, 8, 1)  # SOL_PACKET, PACKET_AUXDATA
    return s


def collect(sockets, expected, timeout=2):
    found = [[] for _ in sockets]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select(sockets, [], [], max(0, deadline - time.monotonic()))
        for s in readable:
            frame, ancillary, _, address = s.recvmsg(65535, 128)
            # Linux can represent VLAN headers as skb metadata. Reconstruct the
            # frame as libpcap does, including VLAN ID 0 (VALID is the authority).
            for level, kind, data in ancillary:
                if level == 263 and kind == 8 and len(data) >= 20:
                    status, _, _, _, _, tci, tpid = struct.unpack('=IIIHHHH', data[:20])
                    if status & (1 << 4):  # TP_STATUS_VLAN_VALID
                        if not status & (1 << 6):  # TP_STATUS_VLAN_TPID_VALID
                            tpid = 0x8100
                        frame = frame[:12] + struct.pack('!HH', tpid, tci) + frame[12:]
            # Ignore outgoing packets; only count actual received frames.
            if address[2] != socket.PACKET_OUTGOING and frame in expected:
                found[sockets.index(s)].append(frame)
    return found


def inner(binary):
    for local, peer in [('eth0', 'up'), ('eth1', 'down')]:
        run('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer)
        for name in (local, peer):
            run('ip', 'link', 'set', 'dev', name, 'up')
    # Prevent background IPv6 DAD/RS frames from confusing the scenario.
    for name in ('eth0', 'eth1', 'up', 'down'):
        with open(f'/proc/sys/net/ipv6/conf/{name}/disable_ipv6', 'w') as f:
            f.write('1')
    sockets = [packet_socket('up'), packet_socket('down')]
    try:
        # Existing clsact must survive shutdown.
        run('tc', 'qdisc', 'add', 'dev', 'eth0', 'clsact')
        with tempfile.TemporaryFile(mode='w+t') as log:
            proc = subprocess.Popen([binary, 'eth0', 'eth1'], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    log.seek(0)
                    if 'ready:' in log.read():
                        break
                    if proc.poll() is not None:
                        raise AssertionError('daemon failed during setup')
                    time.sleep(0.05)
                else:
                    raise AssertionError('daemon readiness timeout')
                tap = packet_socket('conveyor0')
                sockets.append(tap)
                # Unique unknown unicast, broadcast, multicast, tagged VLAN and jumbo-ish frames.
                destinations = [bytes.fromhex(x) for x in ('020000000099', 'ffffffffffff', '01005e000001')]
                frames = []
                for direction in range(2):
                    batch = []
                    for i, dest in enumerate(destinations):
                        source = bytes.fromhex('020000000010')[:-1] + bytes([0x10 + direction])
                        payload = b'conveyor-test:' + bytes([direction, i]) + bytes(range(128))
                        batch.append(dest + source + b'\x88\xb5' + payload)
                    batch.append(destinations[0] + source + b'\x81\x00\x00\x2a\x88\xb5' + b'vlan' * 30)
                    batch.append(destinations[0] + source + b'\x88\xb5' + b'x' * 1500)
                    for frame in batch:
                        sockets[direction].send(frame)
                    received = collect(sockets, batch)
                    assert received[direction] == [], ('reflection', direction, received)
                    assert sorted(received[1 - direction]) == sorted(batch), ('forward', direction, received)
                    assert sorted(received[2]) == sorted(batch), ('mirror', direction, received)
                    frames.extend(batch)
                # Concurrent readers both receive their own complete copy.
                second = packet_socket('conveyor0')
                try:
                    sockets[0].send(frames[0])
                    got = collect([tap, second], [frames[0]])
                    assert got == [[frames[0]], [frames[0]]], got
                finally:
                    second.close()
                # Observer injection cannot enter either physical port.
                injection = bytes.fromhex('ffffffffffff02000000008888b5') + b'observer-only' * 8
                tap.send(injection)
                assert collect(sockets[:2], [injection], 0.3) == [[], []]
                # Refuse collisions without replacing an active instance.
                failed = subprocess.run([binary, 'eth0', 'eth1'], capture_output=True)
                assert failed.returncode != 0
                # A failure after creating a new observer rolls its resources back,
                # while preserving the first instance's filter and capture device.
                failed = subprocess.run([binary, 'eth0', 'eth1', 'failedtap'], capture_output=True)
                assert failed.returncode != 0
                assert subprocess.run(['ip', 'link', 'show', 'failedtap'], capture_output=True).returncode != 0
                sockets[0].send(frames[0])
                got = collect(sockets, [frames[0]])
                assert got == [[], [frames[0]], [frames[0]]], got
                # An unavailable observer must not stop inline forwarding.
                run('ip', 'link', 'set', 'conveyor0', 'down')
                sockets[0].send(frames[0])
                got = collect(sockets[:2], [frames[0]])
                assert got == [[], [frames[0]]], got
            finally:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise
                log.seek(0)
                output = log.read()
                print(output)
            assert proc.returncode == 0, output
        assert subprocess.run(['ip', 'link', 'show', 'conveyor0'], capture_output=True).returncode != 0
        for name in ('eth0', 'eth1'):
            assert 'bpf' not in run('tc', 'filter', 'show', 'dev', name, 'ingress').stdout
            assert 'PROMISC' not in run('ip', 'link', 'show', name).stdout
        assert 'clsact' in run('tc', 'qdisc', 'show', 'dev', 'eth0').stdout
        # A second launch succeeds after clean teardown.
        proc = subprocess.Popen([binary, 'eth0', 'eth1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 5)
            assert ready and 'ready:' in proc.stdout.readline()
        finally:
            proc.terminate()
            proc.communicate(timeout=5)
        assert proc.returncode == 0
        print('PASS: bidirectional forwarding, exact mirrors, multiple readers, isolation, collision, cleanup, restart')
    finally:
        for s in sockets:
            s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=os.path.abspath('build/conveyor'))
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        inner(args.binary)
        return
    if os.geteuid() != 0:
        sys.exit('Integration tests require root (or run nix build .#checks.x86_64-linux.integration).')
    namespace = 'conveyor-test-' + uuid.uuid4().hex[:8]
    run('ip', 'netns', 'add', namespace)
    try:
        subprocess.run(['ip', 'netns', 'exec', namespace, sys.executable, os.path.abspath(__file__),
                        '--inside', '--binary', args.binary], check=True)
    finally:
        run('ip', 'netns', 'del', namespace)


if __name__ == '__main__':
    main()
