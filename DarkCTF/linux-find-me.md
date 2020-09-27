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
kaffarell

# CTF
DarkCTF 2020

# Category
Linux

# Challenge Name
Find-Me

# Challenge Points
321 pts

# Challenge Description
Mr. Wolf was doing some work and he accidentally deleted the important file can you help him and read the file? Note: All players will get individual container
ssh ctf@findme.darkarmy.xyz -p 10000 password: wolfie

# Attachments
_None_

# Solution
As I searched around the system for any hinds, I executed ps and saw that there was a tail process running. 

In Linux all processes have their own directory with info and resources that they use. These Directories are available in the /proc folder. So I navigated to /proc/10 because 10 is the pid of the process. Here we can see all the info and the resources that the process is using. Interesting here is the fd folder, it stands for file descriptor and stores a link to the used files. The third file used (file name 3, execute ls -la to see link) has a link to /home/wolfie1/pass (deleted). So we can execute cat 3 to read the cached link and get a password. 

This is the password of the second user of the system: wolf2. So we try to connect to that user with su wolf2 and the password is correct. This user has a lot of (mostly empty) folders to distract us. But after a brief search you can find the flag in the folder /proc/g. The flag is reversed, but after putting it in the right form it works.