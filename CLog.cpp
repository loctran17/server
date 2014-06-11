#include "CLog.h"

const char* levelString[] =
{
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG",
	"DEBUG1"
	"DEBUG2",
	"DEBUG3",
	"DEBUG4"
};

CLog::CLog()
{
	logLevel = logDEBUG;
}


CLog::~CLog()
{
}

void NowTime()
{
	time_t t = time(0);   // get time now
	struct tm * now = localtime(&t);
	std::cout << (now->tm_year + 1900) << '-'
		<< (now->tm_mon + 1) << '-'
		<< now->tm_mday << ' '
		<< now->tm_hour << ':'
		<< now->tm_min << ':'
		<< now->tm_sec << ' ';
}

void CLog::Get(TLogLevel logVal, const char* message)
{
	if (logVal <= logINFO)
	{
		NowTime();
		std::cout << levelString[logVal] << ": ";
		std::cout << message << std::endl;
	}
}
