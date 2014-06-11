#ifndef CSERVER_H_
#define CSERVER_H_
#include "CLog.h"
#include "CDateTime.h"


class CServer {
public:
	CServer();
	CServer(const char* databasePath);
	virtual ~CServer();
	
	bool Start(int iPort);
	bool Run();
	bool Stop();
	bool LoadCertificates(char* CertFile, char* KeyFile, char* CAFile);

private:
	SSL_CTX		*m_ctx;
	BIO     	*m_acc;
	const char* m_dataPath; 		
	CLog		userLog;
};

#endif
