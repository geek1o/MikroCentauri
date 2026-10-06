#!/usr/bin/env python3
"""A malformed peer must leave valid guests and their packet capture intact."""
import pathlib, socket, struct, subprocess, sys, tempfile, time
ROOT = pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as directory:
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    capture = pathlib.Path(directory) / 'frames.pcap'
    process = subprocess.Popen([sys.executable, str(ROOT/'scripts/lab-switch.py'), '--port', str(port), '--capture', str(capture)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    peers = []
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                peers.append(socket.create_connection(('127.0.0.1', port), timeout=2)); break
            except OSError:
                if time.monotonic() >= deadline: raise
                time.sleep(.02)
        peers.append(socket.create_connection(('127.0.0.1', port), timeout=2))
        bad = socket.create_connection(('127.0.0.1', port), timeout=2)
        bad.sendall(struct.pack('!I', 65536)); assert bad.recv(1) == b''; bad.close()
        packet = bytes.fromhex('ffffffffffff5254008800100800') + b'preserved-guest'
        framed = struct.pack('!I', len(packet)) + packet
        peers[0].sendall(framed)
        received = b''
        while len(received) < len(framed):
            chunk = peers[1].recv(len(framed)-len(received)); assert chunk; received += chunk
        assert received == framed
        assert process.poll() is None
    finally:
        for peer in peers: peer.close()
        process.terminate(); process.wait(timeout=5)
    assert process.returncode == 0, process.stderr.read()
    assert packet in capture.read_bytes()
print('PASS malformed peer isolation and valid Ethernet forwarding/capture')
