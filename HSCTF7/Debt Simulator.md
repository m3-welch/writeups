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
peachyboi

# CTF
HSCTF 7

# Category
Web

# Challenge Name
Debt Simulator

# Challenge Points
100 pts

# Challenge Description
https://debt-simulator.web.hsctf.com/

# Attachments
_None_

# Solution
## The JS File
I started by using the 'Inspect Element' tool in the browser to look at the HTML. There was nothing of interest, except for a JavaScript file: https://debt-simulator.web.hsctf.com/static/js/main.1b8f0187.chunk.js.

## The API
This was a minified JS file, but seemed to contain this URL which stood out: https://debt-simulator-login-backend.web.hsctf.com/yolo_0000000000001.

## Getting the flag
This was an API being called with the functions `getCost` and `getPay`, which correspond to the addition and removal of money on the front-end of the application. 
Performing a simple `GET` request to this URL (can be done by accessing it through the browser), shows us a list of functions, one of which being `getgetgetgetgetgetgetgetgetFlag`. 
I then used a tool called [Postman](https://www.postman.com/) to create a request to the URL (https://debt-simulator-login-backend.web.hsctf.com/yolo_0000000000001) with the HTTP Header `function: getgetgetgetgetgetgetgetgetFlag`. 

This returned the flag to me:
`flag{y0u_f0uND_m3333333_123123123555554322221}`
