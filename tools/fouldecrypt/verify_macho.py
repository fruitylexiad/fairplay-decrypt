#!/usr/bin/env python3
"""Compare original and output Mach-O files without modifying either."""
import hashlib
import struct
import sys
from pathlib import Path

def inspect(data):
    def slice_info(base, length):
        if base < 0 or length < 28 or base + length > len(data):
            raise ValueError("slice outside file")
        magic, = struct.unpack_from("<I", data, base)
        header = 32 if magic == 0xfeedfacf else 28 if magic == 0xfeedface else 0
        if not header or length < header:
            raise ValueError("unsupported Mach-O")
        count, commands_size = struct.unpack_from("<II", data, base + 16)
        if count > 4096 or header + commands_size > length:
            raise ValueError("invalid load commands")
        at, end, commands = header, header + commands_size, []
        for _ in range(count):
            if at + 8 > end:
                raise ValueError("truncated command")
            cmd, size = struct.unpack_from("<II", data, base + at)
            if size < 8 or size % 4 or at + size > end:
                raise ValueError("invalid command length")
            if cmd in (0x21, 0x2c):
                if size < (24 if cmd == 0x2c else 20) or commands:
                    raise ValueError("invalid/duplicate encryption command")
                off, amount, cryptid = struct.unpack_from("<III", data, base + at + 8)
                if off + amount > length:
                    raise ValueError("encrypted range outside slice")
                commands.append(dict(base=base, size=length, cryptoff=off,
                                     cryptsize=amount, cryptid=cryptid,
                                     flag=base + at + 16))
            at += size
        if at != end:
            raise ValueError("load command size mismatch")
        return commands
    if len(data) < 28:
        raise ValueError("file too small")
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        count, = struct.unpack_from(endian + "I", data, 4)
        if not 0 < count <= 32 or 8 + count * 20 > len(data):
            raise ValueError("invalid FAT header")
        result, spans = [], []
        for i in range(count):
            _, _, off, size, _ = struct.unpack_from(endian + "IIIII", data, 8 + i * 20)
            if off < 8 + count * 20 or any(off < b + s and b < off + size for b, s in spans):
                raise ValueError("overlapping FAT slices")
            spans.append((off, size))
            result += slice_info(off, size)
        return result
    return slice_info(0, len(data))

def verify(original, output):
    if len(original) != len(output):
        raise ValueError("file sizes differ")
    before, after = inspect(original), inspect(output)
    if len(before) != len(after) or not before:
        raise ValueError("encryption command count differs/missing")
    allowed, checked = [], 0
    for a, b in zip(before, after):
        if any(a[k] != b[k] for k in a if k != "cryptid"):
            raise ValueError("encryption metadata changed unexpectedly")
        if b["cryptid"] != 0:
            raise ValueError("output still has cryptid != 0")
        if a["cryptid"]:
            start, end = a["base"] + a["cryptoff"], a["base"] + a["cryptoff"] + a["cryptsize"]
            if not a["cryptsize"] or original[start:end] == output[start:end]:
                raise ValueError("cryptid cleared but encrypted bytes did not change")
            allowed += [(start, end), (a["flag"], a["flag"] + 4)]
            checked += 1
    if not checked:
        raise ValueError("original has no encrypted slices")
    at = 0
    for start, end in sorted(allowed):
        if start < at:
            raise ValueError("overlapping permitted ranges")
        if original[at:start] != output[at:start]:
            raise ValueError("bytes outside encrypted region/cryptid changed")
        at = end
    if original[at:] != output[at:]:
        raise ValueError("trailing bytes changed")
    return before, after

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_macho.py ORIGINAL OUTPUT")
    p, q = map(Path, sys.argv[1:])
    if p.resolve() == q.resolve():
        raise SystemExit("input and output must differ")
    original, output = p.read_bytes(), q.read_bytes()
    try:
        before, after = verify(original, output)
    except (ValueError, struct.error) as error:
        raise SystemExit("FAIL: " + str(error))
    for a, b in zip(before, after):
        print("slice=%#x cryptoff=%#x cryptsize=%#x cryptid=%d -> %d" %
              (a["base"], a["cryptoff"], a["cryptsize"], a["cryptid"], b["cryptid"]))
    print("original SHA256:", hashlib.sha256(original).hexdigest())
    print("output   SHA256:", hashlib.sha256(output).hexdigest())
    print("PASS: output cryptid=0; encrypted bytes changed; other bytes preserved.")
    print("This verifies structure and changes, not full plaintext correctness or app launchability.")

if __name__ == "__main__":
    main()
