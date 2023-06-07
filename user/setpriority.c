#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("error:usuage is wrong");
        exit(1);
    }

    int new_static_priority = atoi(argv[1]);
    int pid = atoi(argv[2]);

    int old_static_priority = set_priority(new_static_priority, pid);
    if (old_static_priority == -1)
        exit(1);
    return old_static_priority;
}
