#include "CDateTime.h"


CDateTime::CDateTime()
{
	
}


CDateTime::~CDateTime()
{
}

void CDateTime::Start(TimerHandler* t)
{
	struct timeval temp;
	gettimeofday(&temp, NULL);
	t->currentSeconds = temp.tv_sec;
}

bool CDateTime::Register(TimerHandler* t)
{
	//add current time value to the expiration time of the timer (which was relative
	//when the timer was created to an absolute time ....)
	Start(t);
	timeline.push(t);
	return true;
}

void CDateTime::processNextEvent(void)
{
	if (!this->timeline.empty())
	{
		//we have to check if there is any timer(s) that needs to fire
		TimerHandler *timer = this->timeline.top();
		if (Expired(timer)) // time has passed for the timer
		{
			callback(timer);
			timeline.pop();
			delete timer;
		}
	}
}
unsigned int  CDateTime::GetExpirationTime(TimerHandler*t)
{
	return t->expiry;
}

void  CDateTime::SetExpirationTime(TimerHandler* t, unsigned int expireSeconds)
{
	t->expiry = expireSeconds;
}

bool CDateTime::Expired(TimerHandler* t)
{
	struct timeval temp;
	gettimeofday(&temp, NULL);
	unsigned int time_diff = (temp.tv_sec - t->currentSeconds);
	if (time_diff >= t->expiry)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void CDateTime::callback(TimerHandler* t)
{
	/* Reset login attempt */
	t->m_Db.m_Subcribers.UpdateLoginAttempts(t->m_User.username, 0);
	t->m_Db.Save();
}

void CDateTime::SetUser(TimerHandler*t, User u)
{
	t->m_User = u;
}

User CDateTime::GetUser(TimerHandler*t)
{
	return t->m_User;
}

void CDateTime::SetDb(TimerHandler*t, CDb db)
{
	t->m_Db = db;
}

CDb CDateTime::GetDb(TimerHandler*t)
{
	return t->m_Db;
}