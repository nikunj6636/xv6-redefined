#include "user/user.h"
#include <stddef.h>

int main(int argc,char* argv[]){
    char* array[100];
    int i=2;
    int array_ptr=0;
    // there are less arguments mentioned in the input 
    if (argc < 3){
        fprintf(2, "Usage is wrong: strace mask commands [args]\n");
        exit(1); // to exit the program
    }
    while(argv[i]!=NULL) array[array_ptr++]=argv[i++];
    array[array_ptr]=NULL;
    int p = fork(); // create a child process to execute the commmand given in the input
    if (p == 0){
        int var = atoi(argv[1]); // string to integer conversion
        trace(var);  // calling strace
        exec(argv[2], array); // executing the program
        exit(0);
    }
    wait(0); // waiting for the execution 
    return 0;
}