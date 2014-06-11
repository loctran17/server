#include "TimerHandler.h"
#include "Scheduler.h"

Scheduler::Scheduler() {
	// TODO Auto-generated constructor stub

}

Scheduler::~Scheduler() {
	// TODO Auto-generated destructor stub
}


bool Scheduler::Register(TimerHandler* t)
{
	//add current time value to the expiration time of the timer (which was relative
	//when the timer was created to an absolute time ....)
	t->Start();
	timeline.push(t);
	return true;
}

void Scheduler::processNextEvent()
{
	if (this->timeline.empty())
	{
	    
	}
	else
	{
	  //we have to check if there is any timer(s) that needs to fire
	  TimerHandler *timer = this->timeline.top();
	  if (timer->Expired()) // time has passed for the timer
	  {
		timer->callback();
		timeline.pop();
		delete timer;
	  }
	}
}
