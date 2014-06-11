#include "CLog.h"
#include "CSslConnection.h"

extern CLog userLog;

CSslConnection::CSslConnection(SSL *ssl)
{
	m_ssl = ssl;
}

CSslConnection::~CSslConnection()
{
	if (SSL_get_shutdown(m_ssl) & SSL_RECEIVED_SHUTDOWN)
	{
		SSL_shutdown(m_ssl);
	}
	else
	{
		SSL_clear(m_ssl);
	}
	SSL_free(m_ssl);
}

bool CSslConnection::Send(char *pBuf, int iLen, bool bPrint)
{
	int remainingBytes = iLen;
	char logMsg[256];

	while (remainingBytes > 0)
	{
		int bytes = SSL_write(m_ssl, pBuf, iLen);
		if (bytes <= 0)
		{
			userLog.Get(logERROR, "[-] CServer::SetupClient: SSL_write failed");
			return false;
		}
		remainingBytes = iLen - bytes;
	}
	
	if (bPrint)
	{
		/* sprintf(logMsg, "[+] Sending Packet : %s", pBuf); */
		userLog.Get(logDEBUG, logMsg);
	}
	return true;
}

bool CSslConnection::Recv(char *pBuf, int iLen, bool bPrint)
{
	int bytes = SSL_read(m_ssl, pBuf, iLen);
	pBuf[bytes] = 0;
	char logMsg[256];

	if (bytes <= 0)
	{
		userLog.Get(logERROR, "[-] CServer::Recv: SSL_read failed");
		return bytes;
	}

	if (bPrint)
	{
		/* sprintf(logMsg, "[+] Received Packet: %s", pBuf); */
		userLog.Get(logDEBUG, logMsg);
	}

	return bytes;
}
