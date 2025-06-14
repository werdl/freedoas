# freedoas
> cross-platform clone of OpenBSD's doas
## DO NOT USE FREEDOAS FOR ACTUAL USE YET!!
- freedoas is NOT extensively tested
- i test for segfaults and memory leaks, but not for security
- i am a student, not a security expert
- i am not responsible for any damage caused by this software
- if you want to use it, i strongly recommend you to either use opendoas, or if you want to use this one, ensure that a. you know what you are doing and b. you delete the binary after you are done with it (unless you want to leave a random setuid binary on your system)
## Why?
- freedoas is designed to be as portable as possible, and to be as near possible to OpenBSD's doas
- it is written in C, and uses only POSIX-compatible libraries, thus it should compile on any POSIX-compatible system
- the only non-POSIX feature it uses it `passwd.pw_passwd`, but if a platform does not support it, please post an issue and i will add a workaround, like using `getspnam` for linux
## Features
- freedoas aims to be a drop-in replacement for OpenBSD's doas
- it currently supports all but the following features of OpenBSD's doas:
  - preservation of specific environment variables
- it does not and will not support the `-a` flag, but will allow it to ensure compatibility with scripts that use it
## Installation
- freedoas is a single C file for easy compilation
- alternatively, a Makefile is provided for easy compilation
- use `make dev` to compile the development version, which includes debugging helpers and is not stripped
- use `make release` to compile the release version, which is stripped and does not include debugging helpers
- use `make install` to install the binary to `/usr/local/bin/freedoas`, as well as the man files to correct locations (check Makefile if you want to change the install locations, you need to on OpenBSD for example)
