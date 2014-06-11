#pragma once
#include "Includes.h"

enum TLogLevel {
	logERROR, logWARNING, logINFO, logDEBUG, logDEBUG1,
	logDEBUG2, logDEBUG3, logDEBUG4
};


class CLog
{
private:
	TLogLevel	logLevel;
public:
	CLog();
	virtual ~CLog();
public:
	void Get(TLogLevel, const char*);

};

