# ebpf-disasm

eBPF disassembler and assembler written in Lua

## Disassembler

Reads an hexadecimal dump of eBPF code and transforms it to readable eBPF source code. Example:

```bash
$ objdump -s -j prog data/xdp_ipv6_filter.o | ./bin/ebpf-disasm
```

```asm
ldxw r2, [r1+0x4]
ldxw r1, [r1+0x0]
mov64 r3, r1
add64 r3, 0xe
jge r2, r3, +0xf
lddw r1, 0x0a324c20657372
stxdw [r10+0xfff0], r1
lddw r1, 0x617020746f6e6e61
stxdw [r10+0xffe8], r1
lddw r1, 0x43203a6775626544
stxdw [r10+0xffe0], r1
mov64 r1, r10
add64 r1, 0xffffffe0
mov64 r2, 0x18
call 0x6
mov64 r0, 0x2
ja +0x17
ldxb r2, [r1+0xc]
ldxb r6, [r1+0xd]
mov64 r1, 0xa
stxh [r10+0xfff4], r1
mov64 r1, 0x78257830
stxw [r10+0xfff0], r1
lddw r1, 0x3a657079745f6874
stxdw [r10+0xffe8], r1
lddw r1, 0x65203a6775626544
stxdw [r10+0xffe0], r1
lsh64 r6, 0x8
or64 r6, r2
mov64 r3, r6
be16 r3
mov64 r1, r10
add64 r1, 0xffffffe0
mov64 r2, 0x16
call 0x6
mov64 r0, 0x2
jeq r6, 0xdd86, +0x1
mov64 r0, 0x1
exit
```
## Assembler

Read an input eBPF source code program and transforms it to binary code. Example:

```bash
$ bin/ebpf-asm data/xdp_ipv6_filter.ebpf
output.bin
```

Open output file with Vim in hexadecimal mode:

```bash
$ vim output.bin
%!xxd
00000000: 6112 0400 0000 0000 6111 0000 0000 0000  a.......a.......
00000010: bf13 0000 0000 0000 0703 0000 0e00 0000  ................
00000020: 3d32 0f00 0000 0000 1801 0000 7273 6520  =2..........rse 
00000030: 0000 0000 4c32 0a00 7b1a f0ff 0000 0000  ....L2..{.......
00000040: 1801 0000 616e 6e6f 0000 0000 7420 7061  ....anno....t pa
00000050: 7b1a e8ff 0000 0000 1801 0000 4465 6275  {...........Debu
00000060: 0000 0000 673a 2043 7b1a e0ff 0000 0000  ....g: C{.......
00000070: bfa1 0000 0000 0000 0701 0000 e0ff ffff  ................
00000080: b702 0000 1800 0000 8500 0000 0600 0000  ................
00000090: b700 0000 0200 0000 0500 1700 0000 0000  ................
000000a0: 7112 0c00 0000 0000 7116 0d00 0000 0000  q.......q.......
000000b0: b701 0000 0a00 0000 6b1a f4ff 0000 0000  ........k.......
000000c0: b701 0000 3078 2578 631a f0ff 0000 0000  ....0x%xc.......
000000d0: 1801 0000 7468 5f74 0000 0000 7970 653a  ....th_t....ype:
000000e0: 7b1a e8ff 0000 0000 1801 0000 4465 6275  {...........Debu
000000f0: 0000 0000 673a 2065 7b1a e0ff 0000 0000  ....g: e{.......
00000100: 6706 0000 0800 0000 4f26 0000 0000 0000  g.......O&......
00000110: bf63 0000 0000 0000 dc03 0000 1000 0000  .c..............
00000120: bfa1 0000 0000 0000 0701 0000 e0ff ffff  ................
00000130: b702 0000 1600 0000 8500 0000 0600 0000  ................
00000140: b700 0000 0200 0000 1506 0100 86dd 0000  ................
00000150: b700 0000 0100 0000 9500 0000 0000 0000  ................
00000160: 0a                                       .
```
