**xv6 Dependent Operating System**

An extension of the [MIT](https://github.com/mit-pdos)'s [xv6 Operating System for RISC-V](https://github.com/mit-pdos/xv6-riscv). Read the original readme [here](README).

## Installation

You can follow the install instructions [here](https://pdos.csail.mit.edu/6.S081/2020/tools.html). (Skip the Athena part)

## Running the OS

```sh
$ make clean
$ make qemu SCHEDULER=[RR/PBS/FCFS] CPUS=[N_CPU]
```

default scheduler is RR (Round-robbin).

# Modifications

Here are the modifications made to the original xv6:

## Modification 1: Syscall Tracing

Aims to intercept and record the system calls which are called by a process during its execution. We define a user program called `strace` which uses the system call `trace`.

### User Program

Running:
```sh
$ strace [mask] [command] [args]
```

Implementation:
```c
void strace(int mask, char *command, char *args[]);
```

First, we fork the current process. The parent process waits for the child process. In the child process, before we execute the command using `exec`, we run the `trace` syscall with mask as a parameter.

### System Call

```c
int trace(int mask);
```

There is a 'trace_mask' defined for the proc struct, which is by default set to 0. Every time a process is forked, the child inherits its parent's trace_mask.

When this syscall is called, it takes the input argument which it sets to the `proc->trace_mask`.

For every set bit, the syscall() function in syscall.c prints the information for the syscall corresponding to that bit.

## Modification 2: Sigalarm and Sigreturn 
Sigalram: Aims to alert the processas it uses the CPU time. We define a user program called `alarm` which uses the system call `sigalarm` to implement 
primitive form of user-level interrupt/fault handlers like the `SIGCHILD` handler.

Sigreturn: Resets the process state to before the handler was called.

### User Program

Implementation:
```c
alarm(n, fn)
sigreturn();
```

### System Call

```c
int sigalarm(int ticks, void (*handler)());
int sigreturn(void);
```

## Modification 3: Scheduling

### First Come - First Served

We compare the creation time of each process (which is stored in proc->ctime and initialized to 0 when the process is allocated in the table).

Then we schedule the process with the minimum creation time which is currently in the table.

Since this is non-preempted, a condition is added to ignore the yield() when FCFS is defined.

### Lottery Based Scheduler

Its is a preemptive scheduler that assigns a time slice to the process randomly in proportion to the number of tickets it owns. 

Implement a system call int settickets(int number) , which sets the number of tickets of the calling process.

Calling this routine makes it such that a process can raise the number of tickets it receives, and thus receive a higher proportion of CPU cycles.

### Priority Based Scheduler

Instead of time, we compare the priorities. Static priority (default to 60) can be changed (explained below) by the user. Dynamic priority is calculated and compared:

```c
dynamic_pr = max(0, min(100, static_pr - niceness + 5))
```

where niceness is defined as
```c
10*(ntime)/(ntime+rtime)
```

here ntime (nap time) and rtime (run time) are the ticks spent in sleeping state since the last call/running state in total, stored in proc->ntime and proc->rtime.

#### Set Priority

User program:
```sh
$ setpriority [priority] [pid]
```

which calls the `set_priority` system call which sets the static priority to the given value and resets ntime to 0 and niceness to 5.

```c
int set_priority(int new_priority, int proc_id);
```

### Multi Level Feedback Queue

It allows processes to move between different priority queues based on their behavior and CPU bursts. Aging is implemented to prevent starvation.

If a process voluntarily relinquishes control of the CPU it leaves the queuing network, and when the process becomes ready again after the I/O, it is
inserted at the tail of the same queue, from which it is relinquished earlier

## Modification 4: Copy-on-write fork

The idea behind a copy-on-write is that when a parent process creates a child process by `fork` syscall, then both of these processes initially 

will share the same pages in memory and these shared pages will be marked as copy-on-write which means that if any of these processes

will try to modify  the shared pages then only a copy of these pages will be changed.

*This was built as a part of the Operating Systems and Networks course, Monsoon 2022. The problem statement is given [here](Assignment/xv6.pdf).*
