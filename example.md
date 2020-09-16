# Author
SamIsland (ctftime username)

# CTF
HSCTF 7

# Category
Misc

# Challenge Name
My First Calculator

# Challenge Description
I’m really new to python. Please don’t break my calculator!
nc misc.hsctf.com 7001

There is a flag.txt on the server.

Attachments: [calculator.py](https://pastebin.com/NGickNbp)

# Challenge Points
100 pts

# _*Solution*_
## Code Analysis:
After taking a first look at the source code we can see the script is written in python2.7 and calls a couple of input() methods casted as int() which expect us to pass two operands. After that, a raw_input() method is called, allowing us to pass in the operator.
At this point the script will run the calculation and output the result.

## Vulnerabilities:
In python2.x the input() method has a flaw that allows an attacker to pass in variable names, function names and any other data type. Here you can find more details about it.

## Getting our hands dirty:
Our goal is to read the flag written in the flag.txt file stored on the server BUT we have to keep in mind that both vulnerable inputs are casted as int, so in order not to make the program crash we can only pass in methods that return an integer.
So how can we get the flag if we can only work with integers?
The answer: by reading the decimal value of each character that composes the flag!

In order to make that happen, we first need to know the flag length.
To do that we connect to the server and pass in the following piece of code as the first input: 

len(open('flag.txt', 'r').readline().split()[0])

What it does is simply 
opening the flag.txt file in reading mode
reading its content
splitting the content into a list
selecting the first element of the list (the flag)
returning its length

For the second input we pass 0 as we don’t want to mess up the length value,
and for the third one we can pass either ‘+’ or ‘-’

At this point the script will compute FLAG_LENGTH ± 0, printing out the actual flag length.

Now we are finally ready to read the flag!
We reconnect to the server and repeat the same procedure with a slightly different line of code:

ord(open('flag.txt', 'r').readline()[n])

It does pretty much the same thing as the one above, with the difference that this time we don’t need to get the whole string, so there’s no need to strip() it, and instead of calling len() we call ord() which returns the decimal value of the character at position n.

We still pass 0 and either ‘+’ or ’-’ to the next two inputs and we would get the decimal value of the Nth character of the flag.

All we have to do now is repeat this procedure for every character of the string.
It would take quite a lot of time to do that by hand, so i decided to automatize it with this simple script.

Once we run it, and wait a few seconds we would get the flag:
flag{please_use_python3}
(It's fun since I wrote the script using python2 lmao)
