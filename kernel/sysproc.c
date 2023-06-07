#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_waitx(void)
{
  uint64 addr, addr1, addr2;
  uint wtime, rtime;
  argaddr(0, &addr);
  argaddr(1, &addr1); // user virtual memory
  argaddr(2, &addr2);
  int ret = waitx(addr, &wtime, &rtime);
  struct proc* p = myproc();
  if (copyout(p->pagetable, addr1,(char*)&wtime, sizeof(int)) < 0)
    return -1;
  if (copyout(p->pagetable, addr2,(char*)&rtime, sizeof(int)) < 0)
    return -1;
  return ret;
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64 sys_sigalarm(void){
  int ticks;
  if(argint(0, &ticks) < 0)
    return -1;
  uint64 handler;
  if(argaddr(1, &handler) < 0)
    return -1;
  myproc()->is_sigalarm =0;
  myproc()->ticks = ticks;
  myproc()->now_ticks = 0;
  myproc()->handler = handler;
  return 0; 
}

void restore(){
  struct proc*p=myproc();

  p->trapframe_copy->kernel_satp = p->trapframe->kernel_satp;
  p->trapframe_copy->kernel_sp = p->trapframe->kernel_sp;
  p->trapframe_copy->kernel_trap = p->trapframe->kernel_trap;
  p->trapframe_copy->kernel_hartid = p->trapframe->kernel_hartid;
  *(p->trapframe) = *(p->trapframe_copy);
}

uint64 sys_sigreturn(void){
  restore();
  myproc()->is_sigalarm = 0;
  return myproc()->trapframe->a0;
}

int
sys_set_priority(void)
{
  int priority;
  int pid;

  if (argint(0, &priority) < 0 || argint(1, &pid) < 0)
    return -1;
  return set_priority(priority, pid);
}

uint64 sys_settickets(void){
  int n;
  if(argint(0,&n)<0) return -1;
  return settickets(n);
}

uint64
sys_trace(void)
{
  int a;
  if(argint(0,&a)<0) return -1;
  // retrieve the arguments 
  myproc()->trace_mask = a;
  return 0;
}