/*
 * TimerHandler.h
 *
 *  Created on: Mar 21, 2014
 *      Author: Loc
 */

#ifndef TIMERHANDLER_H_
#define TIMERHANDLER_H_

#include <sys/time.h>
#include "Utils.h"
#include "CSubscribers.h"

class TimerHandler {

public:
	TimerHandler(int sec, User user, CSubscribers sub);
	virtual ~TimerHandler();
private:
	size_t	currentSeconds;
	unsigned int periodic_expiry; //if you have periodic timer, set this to the period, otherwise it should be zero
	CSubscribers m_Sub;
	User		 m_User;

public:
	  void Start();
	  unsigned int  GetExpirationTime();
	  void  SetExpirationTime(unsigned int);
	  bool Expired();
	  void callback();
};

#endif /* TIMERHANDLER_H_ */
