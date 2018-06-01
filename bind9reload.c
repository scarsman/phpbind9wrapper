#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {

   printf("Process Id is: %d\n",getpid());
   printf("geteuid: %d\n",geteuid());

  if (setuid(geteuid()) == 0) {
    system("/etc/init.d/bind9  reload > /dev/null 2>&1;/etc/init.d/bind9 status > /tmp/bind9status");
  } else {
    printf("Couldn't set UID to effective UID");
    return 1;
  }
  return 0;

}
