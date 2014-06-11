#pragma once
#include "Includes.h"
#include "CDb.h"

typedef struct TimerHandler
{
	size_t	currentSeconds;
	unsigned int expiry; /* seconds unit */
	CDb			m_Db;
	User		 m_User;
}TimerHandler;


struct TimerHandlerComparision   //used in the priority queue to compare timers
{
	bool operator()(TimerHandler *x, TimerHandler *y)
	{
		unsigned int tx = x->expiry, ty = y->expiry;
		return (tx > ty);
		//return ((*x) > (*y));
	}
};

class CDateTime
{
public:
	CDateTime();
	~CDateTime();

public:
	
	bool Register(TimerHandler*);
	void processNextEvent(void);
	unsigned int  GetExpirationTime(TimerHandler*);
	void  SetExpirationTime(TimerHandler*, unsigned int);
	bool Expired(TimerHandler*);
	void SetUser(TimerHandler*, User );
	User GetUser(TimerHandler*);
	void SetDb(TimerHandler*, CDb);
	CDb GetDb(TimerHandler*);
	void callback(TimerHandler*);
	void Start(TimerHandler*);

private:
	std::priority_queue<TimerHandler*, std::vector<TimerHandler*>, TimerHandlerComparision> timeline;

};

