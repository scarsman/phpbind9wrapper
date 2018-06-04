#include <stdio.h>
#include <stdlib.h>

/*
*returned ok if the zone file is OK
*/

int main(int argc, char * argv[]) {
        if(!(setuid(geteuid()))) {
                system("/usr/sbin/named-checkzone "+argv[1] + " " + argv[2]);
        }else{
                printf("Couldn't set UID to effective UIDn. Couldn't");
                return 1;       
        } 
        
        return 0;
}
