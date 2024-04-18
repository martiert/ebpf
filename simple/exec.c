#include "exec.skel.h"
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>


static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT: %s\n", strerror(errno));
        exit(1);
    }
}

int main()
{
   bump_memlock_rlimit();
   
   struct exec * skel = exec__open();
   exec__load(skel);
   exec__attach(skel);

    for(;;) {
    }
    return 0;
}
