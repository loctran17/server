#ifndef CSSLCONNECTION_H_
#define CSSLCONNECTION_H_

#include "Includes.h"

class CSslConnection {
public:
	CSslConnection(SSL *ssl);
	virtual ~CSslConnection();

	// Add SSL parameter for multithreading
	bool Send(char* pBuf, int iLen, const bool bPrint = 1);
	bool Recv(char* pBuf, int iLen, const bool bPrint = 1);

private:
	SSL	*m_ssl;
};

#endif
