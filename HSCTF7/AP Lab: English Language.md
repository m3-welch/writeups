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
RE

# Challenge-Name
AP Lab: English Language

# Challenge-Points
100 pts

# Challenge-Description
The AP English Language activity will ask you to reverse a program about manipulating strings and arrays.
Again, an output will be given where you have to reconstruct an input.

# Attachments
_Unknown_

# Solution

So the java program takes an input, changes the input with two functions (xor and transpose) and then compares it to a specific string.
So we have to reverse the xor and the transpose function to get the input correct.
The input will then be the flag. So I first started reversing the xor function, which was pretty easy and then the transpose function, which was a little bit harder.

``` python
def xor(ret):
    xor_list = [4,1,3,1,2,1,3,0,1,4,3,1,2,0,1,4,1,2,3,2,1,0,3]
    inp = [None] * (len(ret))
    ret = list(ret)
    for i in range(0, len(ret)):
        inp[i] = chr(ord(ret[i]) ^ xor_list[i])
    return inp

def transpose(ret):
    transpose = [11,18,15,19,8,17,5,2,12,6,21,0,22,7,13,14,4,16,20,1,3,10,9]
    inp = [None] * (len(ret))
    counter = 0
    for i in transpose:
        inp[i] = ret[counter]
        counter = counter + 1
    return inp


#output = "1dd3|y_3tttb5g`q]^dhn3j"
output_string = input()
inp = list(str(output_string))
print("String at the beginnning: ", inp)
for i in range(0, 3):
    inp = xor(inp)
    print("After xor: ", inp)
    inp = transpose(inp)
    print("After transpose: ", inp)

# output as a string
print(' '.join([str(elem) for elem in inp]))
```
This is the python program I wrote to reverse the output to the input.

`flag{n0t_t00_b4d_r1ght}`
