#include "CServer.h"
#include <iostream>
#include <string>
#include <thread>
#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

using namespace std;
using namespace boost;
using namespace boost::property_tree;

CDateTime sched;
CLog	  userLog;
bool ServerStartup(CServer *Server, char *CertFile, char *KeyFile, char* CAFile)
{
	/* Start, LoadCertificates , LoadCA */
	if (Server->Start(1340) == 0)
	{
		cout << "Server->Start failed" << endl;
		return 0;
	}

	if (Server->LoadCertificates(CertFile, KeyFile, CAFile) == 0)
	{
		cout << "LoadCertificates failed" << endl;
		return false;
	}

	return true;
}

void Timer_Scheduler()
{
	while (1)
		sched.processNextEvent();
}
CServer	*pServer;
void Server_Run()
{
	pServer->Run();
}

int main(int argc, char* argv[])
{

	
	char* KeyFile;
	char* CertFile;
	char* CAFile;
	char* DbPath;

	/* Certificat file */
	if (argc < 2)
	{
		CertFile = (char*)("/root/Server/server.pem");
	}
	else
	{
		CertFile = argv[1];
	}
	/* Key file */
	if (argc < 3)
	{
		KeyFile = (char*)("/root/Server/server.pem");
	}
	else
	{
		KeyFile = argv[2];
	}
	/* CA file */
	if (argc < 4)
	{
		CAFile = (char*)("/root/Server/rootcert.pem");
	}
	else
	{
		CAFile = argv[3];
	}
	/* DB file */
	if (argc < 5)
	{
		DbPath = (char*)("/root/Server/database.dat");
	}
	else
	{
		DbPath = argv[4];
	}
	pServer = new CServer((const char*)DbPath);

	if (!ServerStartup(pServer, CertFile, KeyFile, CAFile))
		return 0;
	
	std::thread t1(Timer_Scheduler);
	std::thread t2(Server_Run);

	t1.join();
	t2.join();
	
	pServer->Stop();
	delete pServer;
	
	return 0;
}
