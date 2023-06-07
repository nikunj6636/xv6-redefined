#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include<limits.h>
#include<stddef.h>
#define m 0x80000000

struct cpu cpus[NCPU];

struct proc proc[NPROC];


#ifdef MLFQ
  struct Queue priority_queue[nmlfq];
  int level;
#endif

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    char *pa = kalloc();
    if (pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int)(p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table.
void procinit(void)
{
  struct proc *p;

  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    initlock(&p->lock, "proc");
    p->state = UNUSED;
    p->kstack = KSTACK((int)(p - proc));
  }

  #ifdef MLFQ

  for (int i = 0; i < nmlfq; i++)
  {
    priority_queue[i].size = 0;
    priority_queue[i].head = 0; // head points to first element in the queueu
    priority_queue[i].tail = -1; // tail points to last element in queue
  }

#endif
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu *
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc *
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int allocpid()
{
  int pid;

  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == UNUSED)
    {
      goto found;
    }
    else
    {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  // for FCFS scheduling, waitx
  p->rtime = 0;
  p->etime = 0;
  p->ctime = ticks;
  p->tickets=1;

  // PBS scheduler initialise the priority of the process as 60 by default
  p->priority = 60;
  p->num_run = 0;
  p->last_run = 0;
  p->last_sleep = 0;
  p->sched_before = 0;

#ifdef MLFQ
  p->queue_priority = 0; // enters the highest queue
  p->in_queue = 0;
  p->time_quantum = 1; // to prevent it's preemption

  for (int i = 0; i < nmlfq; i++)
    p->qrtime[i] = 0; // runtime in each queue

#endif

  // Allocate a trapframe page.
  if ((p->trapframe = (struct trapframe *)kalloc()) == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  if((p->trapframe_copy = (struct trapframe *)kalloc()) == 0){
    release(&p->lock);
    return 0;
  }
  p->is_sigalarm=0;
  p->ticks=0;
  p->now_ticks=0;
  p->handler=0;

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if (p->pagetable == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if (p->trapframe)
    kfree((void *)p->trapframe);
  p->trapframe = 0;
  if (p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  if(p->trapframe_copy)
    kfree((void*)p->trapframe_copy);
  p->trapframe = 0;
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if (pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if (mappages(pagetable, TRAMPOLINE, PGSIZE,
               (uint64)trampoline, PTE_R | PTE_X) < 0)
  {
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if (mappages(pagetable, TRAPFRAME, PGSIZE,
               (uint64)(p->trapframe), PTE_R | PTE_W) < 0)
  {
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
    0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
    0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
    0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
    0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
    0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// Set up first user process.
void userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;

  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;     // user program counter
  p->trapframe->sp = PGSIZE; // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if (n > 0)
  {
    if ((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0)
    {
      return -1;
    }
  }
  else if (n < 0)
  {
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy user memory from parent to child.
  if (uvmcopy(p->pagetable, np->pagetable, p->sz) < 0)
  {
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;
  np->tickets = p->tickets;
  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void reparent(struct proc *p)
{
  struct proc *pp;

  for (pp = proc; pp < &proc[NPROC]; pp++)
  {
    if (pp->parent == p)
    {
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void exit(int status)
{
  struct proc *p = myproc();

  if (p == initproc)
    panic("init exiting");

  // Close all open files.
  for (int fd = 0; fd < NOFILE; fd++)
  {
    if (p->ofile[fd])
    {
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);

  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;
  p->etime = ticks;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (pp = proc; pp < &proc[NPROC]; pp++)
    {
      if (pp->parent == p)
      {
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if (pp->state == ZOMBIE)
        {
          // Found one.
          pid = pp->pid;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                   sizeof(pp->xstate)) < 0)
          {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || killed(p))
    {
      release(&wait_lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &wait_lock); // DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.


int set_priority(int new_static_priority, int proc_pid)
{
  #ifndef PBS
    printf("Scheduling is not PBS!\n");
    return -1;
  #endif

  struct proc *p;
  int old_static_priority = -1;

  if (new_static_priority < 0 || new_static_priority > 100)
    return -1;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->pid == proc_pid)
    {
      old_static_priority = p->priority;
      p->priority = new_static_priority;
      p->sched_before = 0; // to bring niceness value 5
      break;
    }
  }

  if (old_static_priority != -1)
  {
    if (new_static_priority < old_static_priority) // priority increases, value lowers
    {
      yield(); // called by a process that wishes to give up the CPU after a time interrupt
    }
  }

  return old_static_priority;
}

int settickets(int n){
  struct proc * p = 0;
  p = myproc();
  acquire(&p->lock);
  p->tickets+=n;
  release(&p->lock);
  return 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

int proc_priority(const struct proc *process)
{
  int niceness = 5; // default value
  if (process->sched_before == 1) // process is last_scheduled true
  {
     int sum = process->last_run + process->last_sleep;
     if (sum != 0)
     {
        niceness = ((process->last_sleep) / (sum)) * 10;
     }
  }
  // return the dynamic priority of the process
  return MAX(0, MIN(process->priority - niceness + 5, 100));
}

void scheduler(void)
{
  struct cpu *c = mycpu();
  c->proc = 0;

#ifdef RR // round robin policy implemented
  printf("RR\n");
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
    struct proc* p;
    for (p = proc; p < &proc[NPROC]; p++)
    {
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
      release(&p->lock);
    }
  }
  
#elif defined(FCFS) // FCFS policy implemented
  printf("FCFS\n");
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
    struct proc *p_sched = NULL;

    int min_time = INT_MAX;

    for (struct proc* p = proc; p < &proc[NPROC]; p++)
    {
      // find the process with the least time
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        if (p->ctime < min_time)
        {
          min_time = p->ctime;
          p_sched = p;
        }
      }
      release(&p->lock);
    }

    if (p_sched == NULL) continue;

    acquire(&p_sched->lock);
    if (p_sched->state == RUNNABLE)
    {
      // Switch to chosen process.  It is the process's job
      // to release its lock and then reacquire it
      // before jumping back to us.
      p_sched->state = RUNNING;
      c->proc = p_sched;
      swtch(&c->context, &p_sched->context);
      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&p_sched->lock);
  }

#elif defined(PBS)
  printf("PBS\n");
  for(;;)
  {
    intr_on();

    struct proc *p_sched = NULL;
    uint pbs_priority = -1;

    for (struct proc *p = proc; p < &proc[NPROC]; p++)
    {
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        int priority;
        priority = proc_priority(p); // find the dynamic priority

        if (priority < pbs_priority)
        {
          p_sched = p;
          pbs_priority = priority;
        }

        else if (pbs_priority == priority && p_sched->num_run > p->num_run)
        {
          p_sched = p;
        }

        else if (pbs_priority == priority && p_sched->num_run > p->num_run && p_sched->ctime > p->ctime)
        {
          p_sched = p;
        }
      }
      release(&p->lock);
    }

    if (p_sched == NULL) 
      continue; // nothing to release

    acquire(&p_sched->lock);
    if (p_sched->state == RUNNABLE){
      p_sched->state = RUNNING;

      p_sched->num_run += 1; // number of times it run
      p_sched->last_run = 0; // put 0 as scheduled now
      p_sched->last_sleep = 0;
      p_sched->sched_before = 1;

      c->proc = p_sched;
      swtch(&c->context, &p_sched->context);

      c->proc = 0;
    }
    release(&p_sched->lock);
  }
#elif defined(LBS)
  printf("LBS\n");
  uint64 X = 1;
  uint64 a = 1103515245, no = 12345;
  for(;;){
    intr_on();
    int total_tick=0;
    int no_winner=0;
    struct proc* p;
    int count=0;
    struct proc *p_sched=NULL;
    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state == RUNNABLE) total_tick+=p->tickets; 
      release(&p->lock);
    }
    int r = (X % total_tick) + 1;  
    X = (a*X + no) % m;
    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state == RUNNABLE){
        no_winner+=p->tickets;
        if(no_winner>=r && count==0){
          p_sched=p;
          count=1;
        }
      } 
      release(&p->lock);
    }
    if(p_sched!=NULL){
      acquire(&p_sched->lock);
      if (p_sched->state == RUNNABLE){
        p_sched->state = RUNNING;
        c->proc = p_sched;
        swtch(&c->context, &p_sched->context);
        c->proc = 0;
      }
      release(&p_sched->lock);
    }
    else continue;
  }

#elif defined(MLFQ)
  printf("MLFQ\n");
  for(;;)
  {
    intr_on();
    struct proc *p_sched = NULL;

    // push RUNNABLE processes in queue
    for (struct proc *p = proc; p < &proc[NPROC]; p++)
    {
      if (p->in_queue == 0 && p->state == RUNNABLE)
      {
        p->entry_time = ticks; // added into queue
        qpush(&priority_queue[p->queue_priority], p);
        p->in_queue = 1;
      }
    }

    for (level = 0; level < nmlfq; level++) // iterating over all queue
    {
      while (priority_queue[level].size > 0) // run processes in highest priority_queue
      {
        struct proc *p = top(&priority_queue[level]);

        qpop(&priority_queue[level]); // pop the processes that are waitng for I/O
        p->in_queue = 0; // remove NON RUNNABLE processes from queue

        if (p->state == RUNNABLE)
        {
          p_sched = p;
          break;
        }
      }

      if (p_sched != NULL) break;
    }

    if (p_sched == NULL) continue;

    acquire(&p_sched->lock);
    if (p_sched->state == RUNNABLE)
    {
      p_sched->state = RUNNING;
      p_sched->time_quantum = 1 << p_sched->queue_priority; // preemption time
      c->proc = p_sched;
      swtch(&c->context, &p_sched->context);

      c->proc = 0;
    }
    release(&p_sched->lock);
  }

#endif
}


void update_time(void)
{
  struct proc *p;
  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->state == RUNNING)
    {
      p->last_run++;
      p->rtime++;

      #ifdef MLFQ

        // AGING : Increment Priority
        for (struct proc *p = proc; p < &proc[NPROC]; p++) // running processes
        {
          if (p->in_queue && ticks - p->entry_time > MAXAGE) // in ready queue
          {
            qremove(&priority_queue[p->queue_priority], p->pid); // remove from curr queue
            p->in_queue = 0;

            if (p->queue_priority != 0)  p->queue_priority--; // increasing the priority
          }
        }

        p->qrtime[p->queue_priority]++; // run time in priority_queue

        p->time_quantum--; // to preemt after time quantum of queue
      #endif
    }

    else if (p->state == SLEEPING)
    {
      p->last_sleep++;
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&p->lock))
    panic("sched p->lock");
  if (mycpu()->noff != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first)
  {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock); // DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void wakeup(void *chan)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p != myproc())
    {
      acquire(&p->lock);
      if (p->state == SLEEPING && p->chan == chan)
      {
        p->state = RUNNABLE;
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int kill(int pid)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->pid == pid)
    {
      p->killed = 1;
      if (p->state == SLEEPING)
      {
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int killed(struct proc *p)
{
  int k;

  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if (user_dst)
  {
    return copyout(p->pagetable, dst, src, len);
  }
  
  else
  {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if (user_src)
  {
    return copyin(p->pagetable, dst, src, len);
  }
  else
  {
    memmove(dst, (char *)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [USED] "used",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  struct proc *p;

  char *state;

  printf("\n");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    
    #ifdef MLFQ
    printf("%d %s %s run : %d priority : %d\n", p->pid, state, p->name, p->rtime, p->queue_priority);
    for (int i=0; i<nmlfq; i++)
    {
      printf("%d ", p->qrtime[i]);
    }
    #endif

    #ifdef PBS
    printf("%d %s %s run : %d priority : %d sleep: %d", p->pid, state, p->name, p->rtime, p->priority, p->last_sleep);
    #endif

    #ifdef FCFS
    printf("%d %s %s run : %d ctime : %d", p->pid, state, p->name, p->rtime, p->ctime);
    #endif

    #ifdef LBS
    printf("%d %s %s run : %d tickets : %d", p->pid, state, p->name, p->rtime, p->tickets);
    #endif

    #ifdef RR
    printf("%d %s %s run : %d", p->pid, state, p->name, p->rtime);
    #endif


    printf("\n");
  }
}

int
waitx(uint64 addr, uint* wtime, uint* rtime)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(np = proc; np < &proc[NPROC]; np++){
      if(np->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&np->lock);

        havekids = 1;
        if(np->state == ZOMBIE){
          // Found one.
          pid = np->pid;
          *rtime = np->rtime;
          *wtime = np->etime - np->ctime - np->rtime;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                  sizeof(np->xstate)) < 0) {
            release(&np->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&wait_lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || p->killed){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Queue functions

#ifdef MLFQ 

struct proc *top(struct Queue *q)
{
  if (q->size == 0)  return NULL;
  
  return q->procs[q->head]; // return the front element
}

void qpush(Queue *q, struct proc *element)
{
  if (q->size == NPROC)
    panic("Number of Process exceeds");
  q->tail = (q->tail + 1) % NPROC;
  q->procs[q->tail] = element; // insert at the tail of queue
  q->size++;
}

void qpop(struct Queue *q)
{
  if (q->size == 0)
    panic("Empty queue");
  
  q->head = (q->head+1)%(NPROC);
  q->size--;
}

void qremove(Queue *q, int pid)
{
  for (int i = q->head, count = 0; count < q->size; i = (i + 1) % NPROC, count++)
  {
    if (q->procs[i]->pid == pid)
    {
      struct proc *temp = q->procs[i];
      q->procs[i] = q->procs[(i+1)%NPROC];
      q->procs[(i+1)%NPROC] = temp;
    }
  }
  q->tail--;
  if (q->tail < 0) q->tail = NPROC;
  q->size--;
}

#endif

// setpriority 15 13