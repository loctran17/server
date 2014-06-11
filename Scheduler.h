#ifndef SCHEDULER_H_
#define SCHEDULER_H_

#include <iostream>
#include <queue> 
#include "TimerHandler.h"

struct TimerHandlerComparision   //used in the priority queue to compare timers
{
  bool operator()(TimerHandler *x, TimerHandler *y)
  {
	unsigned int tx = x->GetExpirationTime(), ty = y->GetExpirationTime();
	return (tx > ty);
    //return ((*x) > (*y));
  }
};


class Scheduler {
public:
	Scheduler();
	virtual ~Scheduler();
private:
	std::priority_queue<TimerHandler*, std::vector<TimerHandler*>, TimerHandlerComparision> timeline;
public:
	bool Register(TimerHandler*);
	void processNextEvent(void);
};

#endif /* SCHEDULER_H_ */
