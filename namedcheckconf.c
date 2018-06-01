#include <stdio.h>
#include <stdlib.h>

/*
*returned empty if bind configuration is OK else return 1
*/

int main() {
        if(!(setuid(geteuid()))) {
                system("/usr/sbin/named-checkconf /etc/bind/named.conf");
        }else{
                printf("Couldn't set UID to effective UIDn. Couldn't");
                return 1;       
        }
        return 0;
}
