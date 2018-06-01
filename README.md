# phpbind9wrapper
Purpose create a simple dns web hosting

To authenticate user via server system user;
compile the pamlogin wrapper
 - gcc pamlogin.c -g -lpam -o pamlogin
 
For debian, ubuntu, linuxmint - install the security pam module
 - sudo apt-get install libpam0g-dev

To tweak the system call of bind9 service via php
compile the bind9reload.c
- gcc bind9reload.c -o bind9reload
- gcc namedcheckconf.c -o namedcheckconf
- gcc namedcheckzone.c -o namedcheckzone

