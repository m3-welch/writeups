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
SamIsland

# CTF
HSCTF 7

# Category
FOREN

# Challenge-Name
Meta Mountains

# Challenge-Points
100 pts

# Challenge-Description
It seems that mountains are a great place for hiding secrets.
Maybe you could find this one!

# Attachments
## mountains_hsctf.jpg
![Image](https://i.postimg.cc/SQWZvR7k/image.png)

# Solution
As for every forensic challenge that gives you an image i started by running `strings` on the file and grepping for `‘flag’`.

`strings mountains_hsctf.jpg | grep flag`

```
Output:
part 1/3: flag{h1dd3n_w1th1n_
  <tiff:Model>part 1/3: flag{h1dd3n_w1th1n_</tiff:Model>
```

After noticing the flag was made up of 3 parts i just ran the same command but this time grepping for `‘part’` 

`strings mountains_hsctf.jpg | grep part`

```
Output:
part 1/3: flag{h1dd3n_w1th1n_
part 2/3: th3_m0unta1ns_
part 3/3: l13s_th3_m3tadata}
  <tiff:Model>part 1/3: flag{h1dd3n_w1th1n_</tiff:Model>
```
`flag{h1dd3n_w1th1n_th3_m0unta1ns_l13s_th3_m3tadata}`
