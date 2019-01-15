# ebpf-disasm

eBPF disassembler written in Lua

## Example

```bash
$ objdump -s -j prog data/xdp_ipv6_filter.o | ./ebpf_disasm.lua
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
