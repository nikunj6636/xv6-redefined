To run xv6
make clean
make qemu SCHEDULER=[RR/PBS/FCFS/MLFQ/LBS]

Scheduling Policy:        running time:      waiting time:

Round Robin               13                  111
First Come First Serve    30                  36
Priority Based            14                  106
Lotery Based              11                  112
Multi Level Feedback Queue 13                 114

As Average running time of FCFS is highest hence performance of FCFS is worst while performances of all other scheduling algorithm are almost same.