"""
Helper script that attempts to guess the base of an image.

The heuristic attempts to scan the file in search for pointers to strings.

First stage scans the binary for C-strings and collects their file-offsets.

During second stage, the binary is scanned for pointers. The pointers are then
matched with the string offsets by using a mask.

"""
import os
import argparse
import string
import collections


def chunkify(stream, pointer_size, endian):
    while True:
        d = stream.read(pointer_size)
        if len(d) < pointer_size:
            break
        val = int.from_bytes(d, byteorder=endian)
        yield val


def iter_cstrings_raw(stream, delimiter=b"\x00"):
    stream.seek(0)

    pos = 0
    # TODO: reading everything into memory is suboptimal
    for sin in stream.read().split(delimiter):
        yield (pos, sin)
        pos += len(sin) + len(delimiter)


def iter_cstrings(stream, threshold=10):
    charset = string.printable.encode("ascii")
    for s in iter_cstrings_raw(stream):
        if len(s[1]) < threshold:
            continue
        if any(c not in charset for c in s[1]):
            continue
        yield s


def make_mask(n):
    return (1 << n) - 1


def scan_file(stream, endian="little", pointer_size=4, mask=12):
    MASK = make_mask(mask)
    M = {}
    for s in iter_cstrings(stream):
        offset, string = s
        masked_offset = offset & MASK
        if masked_offset not in M:
            M[masked_offset] = []
        M[masked_offset].append(s)
    c = collections.Counter()

    stream.seek(0)
    for chk in chunkify(stream, endian=endian, pointer_size=pointer_size):
        lo = chk & MASK
        if lo in M:
            for off, string in M[lo]:
                base = chk - off
                if base < 0:
                    continue
                c[base] += len(M[lo])
    return c


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--endian", default="little", choices=["little", "big"])
    parser.add_argument("--pointer-size", default=4, choices=[4, 8], type=int)
    parser.add_argument("--mask", default=16, type=int)
    parser.add_argument("-v", "--verbose", default=False, action="store_true")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        result = scan_file(
            f, endian=args.endian, pointer_size=args.pointer_size, mask=args.mask
        )
        best_result = result.most_common(1)[0][0]

        if args.verbose:
            for c in result.most_common(10):
                field_size = 2 * args.pointer_size
                import math

                s = math.ceil(math.log10(result.total()))
                print(
                    f"0x{c[0]:0{field_size}x} {c[1]:>{s}}",
                )
        else:
            print(hex(best_result))


if __name__ == "__main__":
    main()
