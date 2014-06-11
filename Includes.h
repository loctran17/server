#ifndef INCLUDES_H_
#define INCLUDES_H_

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <errno.h>
#include <iostream>
#include <queue> 
#include <sys/time.h>
#include <boost/date_time.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/algorithm/string.hpp>

#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#endif
#include <iomanip>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define FAIL    -1

#ifndef WIN32
#include <pthread.h>
#define THREAD_CC
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
										(entry), reinterpret_cast<void*>(arg))
#else
#include <windows.h>
#define THREAD_CC __cdecl
#define THREAD_TYPE	DWORD
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0,
												(arg));\
												(tid) = GetCurrentThreadId();\
											} while (0)
#endif

#endif
