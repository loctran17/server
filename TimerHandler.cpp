/*
 * TimerHandler.cpp
 *
 *  Created on: Mar 21, 2014
 *      Author: Loc
 */

#include "TimerHandler.h"


TimerHandler::TimerHandler(int sec, User user, CSubscribers sub) {
	periodic_expiry = sec;
	m_User = user;
	m_Sub = sub;
	
}

TimerHandler::~TimerHandler() {
	// TODO Auto-generated destructor stub
}

void TimerHandler::Start()
{
	struct timeval temp;
	gettimeofday(&temp, NULL);
	currentSeconds = temp.tv_sec;
}

unsigned int TimerHandler::GetExpirationTime()
{
	return periodic_expiry;
}

void TimerHandler::SetExpirationTime(unsigned int sec)
{
	periodic_expiry = sec;
}

void TimerHandler::callback()
{
	/* Reset login attempt */
	m_Sub.UpdateLoginAttempts(m_User.username, 0);
}

bool TimerHandler::Expired()
{
	struct timeval temp;
	gettimeofday(&temp, NULL);
	unsigned int time_diff = (temp.tv_sec - currentSeconds);
	if (time_diff >= periodic_expiry)
	{
		return true;
	}
	else
	{
		return false;
	}
}