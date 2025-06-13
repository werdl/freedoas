# freedoas
> cross-platform clone of OpenBSD's doas
## DO NOT USE FREEDOAS FOR ACTUAL USE YET!!
- freedoas is NOT extensively tested
- i test for segfaults and memory leaks, but not for security
- i am a student, not a security expert
- i am not responsible for any damage caused by this software
- if you want to use it, i strongly recommend you to either use opendoas, or if you want to use this one, ensure that a. you know what you are doing and b. you delete the binary after you are done with it (unless you want to leave a random setuid binary on your system)
## Features
- freedoas aims to be a drop-in replacement for OpenBSD's doas
- it currently supports all but the following features of OpenBSD's doas:
  - environment variables (and environment setup more generally)
- it does not and will not support the `-a` flag, but will allow it to ensure compatibility with scripts that use it
