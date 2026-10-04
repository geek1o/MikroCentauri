#!/usr/bin/env python3
"""Build a reproducible RAM-root Linux VM from checksum-pinned Alpine assets."""
import argparse
import gzip
import hashlib
import json
import pathlib
import stat
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/linux-lab'


def read_cpio(blob):
    entries = {}
    offset = 0
    while offset + 110 <= len(blob):
        if blob[offset:offset + 6] != b'070701':
            raise ValueError('Unsupported initramfs CPIO format')
        fields = [int(blob[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        name = blob[offset + 110:offset + 110 + namesize - 1].decode()
        offset = (offset + 110 + namesize + 3) & ~3
        data = blob[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == 'TRAILER!!!':
            break
        entries[name.removeprefix('./')] = (fields[1], data)
    return entries


def write_cpio(entries):
    output = bytearray()
    for inode, (name, (mode, data)) in enumerate(sorted(entries.items()) + [('TRAILER!!!', (0, b''))], 1):
        name_bytes = name.encode() + b'\0'
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0]
        output.extend(b'070701' + ''.join(f'{value:08x}' for value in fields).encode())
        output.extend(name_bytes)
        output.extend(b'\0' * (-len(output) % 4))
        output.extend(data)
        output.extend(b'\0' * (-len(output) % 4))
    output.extend(b'\0' * (-len(output) % 512))
    return bytes(output)


def build(binary=None, payload_dir=None):
    CACHE.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / 'lab/linux/assets.lock.json').read_text())
    for asset in lock['assets']:
        path = CACHE / asset['name']
        if not path.exists():
            temporary = path.with_suffix('.download')
            urllib.request.urlretrieve(asset['url'], temporary)
            temporary.replace(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != asset['sha256']:
            raise ValueError(f'Checksum mismatch for {path.name}: {digest}')
    with tarfile.open(CACHE / 'netboot.tar.gz') as archive:
        (CACHE / 'vmlinuz-virt').write_bytes(archive.extractfile('boot/vmlinuz-virt').read())
        original = archive.extractfile('boot/initramfs-virt').read()
    # Preserve matching kernel drivers, then replace userspace with Alpine rootfs.
    entries = {name: value for name, value in read_cpio(gzip.decompress(original)).items()
               if name.startswith('usr/lib/modules/')}
    with tarfile.open(CACHE / 'rootfs.tar.gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if not name:
                continue
            if member.isdir():
                mode, data = stat.S_IFDIR | member.mode, b''
            elif member.issym():
                mode, data = stat.S_IFLNK | member.mode, member.linkname.encode()
            elif member.isfile() or member.islnk():
                mode, data = stat.S_IFREG | member.mode, archive.extractfile(member).read()
            else:
                continue
            entries[name] = (mode, data)
    entries['init'] = (stat.S_IFREG | 0o755, (ROOT / 'lab/linux/init.sh').read_bytes())
    entries['lib/modules'] = (stat.S_IFLNK | 0o777, b'../usr/lib/modules')
    entries['usr/bin/mc-lab'] = (stat.S_IFREG | 0o755, pathlib.Path(binary).read_bytes()) if binary else (stat.S_IFREG | 0o644, b'')
    if payload_dir:
        payload = pathlib.Path(payload_dir).resolve()
        if not payload.is_dir():
            raise ValueError(f'Payload directory does not exist: {payload}')
        for path in sorted(payload.rglob('*')):
            name = 'lab/' + str(path.relative_to(payload))
            if path.is_symlink():
                raise ValueError(f'Payload symlinks are not supported: {path}')
            if path.is_dir():
                entries[name] = (stat.S_IFDIR | 0o755, b'')
            elif path.is_file():
                entries[name] = (stat.S_IFREG | (path.stat().st_mode & 0o777), path.read_bytes())
    # Ensure parent directories of module entries exist in the merged archive.
    for name in list(entries):
        for parent in pathlib.PurePosixPath(name).parents:
            if str(parent) != '.':
                entries.setdefault(str(parent), (stat.S_IFDIR | 0o755, b''))
    with (CACHE / 'initramfs.gz').open('wb') as destination:
        with gzip.GzipFile(fileobj=destination, mode='wb', mtime=0, filename='') as compressor:
            compressor.write(write_cpio(entries))
    print(CACHE / 'initramfs.gz')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', help='Static linux/amd64 workload executable to install as mc-lab')
    parser.add_argument('--payload-dir', help='Copy optional VM payload files into /lab')
    args = parser.parse_args()
    build(args.binary, args.payload_dir)
