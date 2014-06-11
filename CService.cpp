#include "CService.h"

#include <boost/date_time.hpp>

const std::string currentDateTime()
{
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    
    strftime(buf, sizeof(buf), "%d.%m.%Y", &tstruct);

    return buf;
}

CService::CService(CSslConnection *con, const char* databasePath)
{
	m_con = con;
	m_Db = CDb(databasePath);
}

CService::CService(CSslConnection *con)
{
	m_con = con;
}

CService::~CService()
{
	delete m_con;
}


/* Check user login ... this is the entry point for server processing.
If user login successfully, we will send binary stream 
else return error and pass error code to error handler */
ServiceReturn CService::CheckUser()
{
	char request[DATA_LENGTH];
	char reason[REASON_LENGTH];
	User u, u1;
	

	/* Username */
	Recv(reason, request);
	std::string username(request);
	u.username = username;

	/* Password */
	Recv(reason, request);
	std::string password(request);
	u.password = password;

	/* HWID */
	Recv(reason, request);
	std::string hwID(request);
	u.HWID = hwID;

	/* Version */
	Recv(reason, request);
	std::string version(request);
	u.version = version;

	// Load to update user list
	m_Db.Load();
		
	m_User.username = u.username;
	
	// Check whether user exists
	if (m_Db.m_Subcribers.CheckExistUser(u))
	{
		u1 = m_Db.m_Subcribers.GetUser(u.username);
		if (u1.password.empty() && u1.HWID.empty())
		{
			// Login for first time
			m_Db.m_Subcribers.Update(u1.username, u.password, u.HWID, u.comment, u.version);

			/* Call explicte save function everytime update database */
			m_Db.Save();

			m_User = m_Db.m_Subcribers.GetUser(u.username);
		}
		else if (u1.password.compare(u.password) == 0)
		{
			if (u1.loginAttempts == MAX_LOGIN) return Service_OutofLogin;
			if (u1.version.compare(u.version) > 0)
			{
				unsigned int loginAttempts = u1.loginAttempts + 1;
				m_Db.m_Subcribers.UpdateLoginAttempts(u1.username, loginAttempts);
				m_Db.Save();
				m_User = m_Db.m_Subcribers.GetUser(u.username);
				if (loginAttempts == MAX_LOGIN) return Service_OutofLogin;
				else return Service_OldVersion;
			}
			if (u1.expiryDate < currentDateTime())
			{
				unsigned int loginAttempts = u1.loginAttempts + 1;
				m_Db.m_Subcribers.UpdateLoginAttempts(u1.username, loginAttempts);
				m_Db.Save();
				m_User = m_Db.m_Subcribers.GetUser(u.username);
				if (loginAttempts == MAX_LOGIN) return Service_OutofLogin;
				else return Service_ExpiredDay;
			}
		}
		else
		{
			if (u1.loginAttempts == MAX_LOGIN) return Service_OutofLogin;
			unsigned int loginAttempts = u1.loginAttempts + 1;
			m_Db.m_Subcribers.UpdateLoginAttempts(u1.username, loginAttempts);
			m_Db.Save();
			m_User = m_Db.m_Subcribers.GetUser(u.username);
			if (loginAttempts == MAX_LOGIN) return Service_OutofLogin;
			else return Service_WrongPassword;
		}
	}
	else
	{
		// Handle error
		return Service_UserNotRegister;
	}
	m_User = m_Db.m_Subcribers.GetUser(u.username);
	return Service_Ok;
}

bool CService::OpenBinary(const char* szBinary)
{
	std::ifstream myFile;
	unsigned long length;
	myFile.open(szBinary, std::ios::in | std::ios::binary | std::ios::ate);
	if (myFile.is_open())
	{
		myFile.seekg(0, std::ios::end);
		length = myFile.tellg();
		myFile.seekg(0, std::ios::beg);

		/*
		m_binaryBuffer = new char[m_binaryLength];
		myFile.read(m_binaryBuffer, m_binaryLength);
		*/

		myFile.close();

		if (length > 0)
			return true;
	}
	return false;
}

bool CService::SendBinary(const char* szBinary, bool bPrintProgress)
{
	std::ifstream myFile;
	unsigned long length;
	myFile.open(szBinary, std::ios::in | std::ios::binary | std::ios::ate);

	if (myFile.is_open())
	{
		myFile.seekg(0, std::ios::end);
		length = myFile.tellg();
		myFile.seekg(0, std::ios::beg);

		m_con->Send((char*)(&length), 4, 0);

		const unsigned long packet_size = 16384;
		unsigned long packet_count = length / packet_size;
		unsigned long last_packet_size = length % packet_size;


		for (unsigned long i = 0; i <= packet_count; i++)
		{
			if (bPrintProgress)
			{
				/* Not call loadbar */
				/* loadbar((i * 100) / packet_count, 100); */
			}
			if (i < packet_count)
			{
				char * binaryBuffer = new char[packet_size];
				myFile.read(binaryBuffer, packet_size);
				if (m_con->Send(binaryBuffer, packet_size))
				{
					myFile.seekg(0, std::ios::cur);
					continue;
				}
				delete 	binaryBuffer;
								
			}

			if (i == packet_count)
			{
				char * binaryBuffer = new char[last_packet_size];
				myFile.read(binaryBuffer, last_packet_size);
				
				if (m_con->Send(binaryBuffer, last_packet_size))
				{
					myFile.seekg(0, std::ios::cur);
					delete 	binaryBuffer;
					continue;
				}
				delete 	binaryBuffer;
			}
		}
		myFile.close();
	}
	
	return true;
}

bool CService::OpenDriver(const char* szDriver)
{
	std::ifstream myFile;
	unsigned long length;
	myFile.open(szDriver, std::ios::in | std::ios::binary | std::ios::ate);
	if (myFile.is_open())
	{
		myFile.seekg(0, std::ios::end);
		length = myFile.tellg();
		myFile.seekg(0, std::ios::beg);

		myFile.close();

		if (length > 0)
			return true;
	}
	return false;
}

bool CService::SendDriver(const char* szDriver, bool bPrintProgress)
{
	std::ifstream myFile;
	unsigned long length;
	myFile.open(szDriver, std::ios::in | std::ios::binary | std::ios::ate);

	if (myFile.is_open())
	{
		myFile.seekg(0, std::ios::end);
		length = myFile.tellg();
		myFile.seekg(0, std::ios::beg);

		m_con->Send((char*)(&length), 4, 0);

		const unsigned long packet_size = 16384;
		unsigned long packet_count = length / packet_size;
		unsigned long last_packet_size = length % packet_size;


		for (unsigned long i = 0; i <= packet_count; i++)
		{
			if (bPrintProgress)
			{
				/* Not call loadbar */
				/* loadbar((i * 100) / packet_count, 100); */
			}
			if (i < packet_count)
			{
				char * binaryBuffer = new char[packet_size];
				myFile.read(binaryBuffer, packet_size);
				if (m_con->Send(binaryBuffer, packet_size))
				{
					myFile.seekg(0, std::ios::cur);
					continue;
				}
				delete 	binaryBuffer;

			}

			if (i == packet_count)
			{
				char * binaryBuffer = new char[last_packet_size];
				myFile.read(binaryBuffer, last_packet_size);

				if (m_con->Send(binaryBuffer, last_packet_size))
				{
					myFile.seekg(0, std::ios::cur);
					delete 	binaryBuffer;
					continue;
				}
				delete 	binaryBuffer;
			}
		}
		myFile.close();
	}

	return true;
}

void CService::Send(char* reason, char* pBuf)
{

	m_con->Send(reason, REASON_LENGTH);
	m_con->Send(pBuf, DATA_LENGTH);
}

void CService::Recv(char* reason, char* pBuf)
{
	m_con->Recv(reason, REASON_LENGTH);
	m_con->Recv(pBuf, DATA_LENGTH);
}

void CService::ErrorHandle(ServiceReturn ret)
{
	char 	message[DATA_LENGTH];
	char	reason[REASON_LENGTH];
	char	logMsg[256];

	switch (ret)
	{
	case Service_UserNotRegister:
		strcpy(message, USER_NOT_REG);
		strcpy(reason, REASON_ERROR);
		Send(reason, message);
		userLog.Get(logINFO, USER_NOT_REG);
		break;
	case Service_WrongPassword:
		strcpy(message, WRONG_PASS);
		strcpy(reason, REASON_ERROR);
		Send(reason, message);
		sprintf(logMsg, "User %s %s", m_User.username.c_str(), WRONG_PASS);
		userLog.Get(logINFO, logMsg);
		break;
	case Service_ExpiredDay:
		strcpy(message, EXP_DAY);
		strcpy(reason, REASON_ERROR);
		Send(reason, message);
		sprintf(logMsg, "User %s %s", m_User.username.c_str(), EXP_DAY);
		userLog.Get(logINFO, logMsg);
		break;
	case Service_OldVersion:
		strcpy(message, OLD_VERSION);
		strcpy(reason, REASON_ERROR);
		Send(reason, message);
		sprintf(logMsg, "User %s %s", m_User.username.c_str(), OLD_VERSION);
		userLog.Get(logINFO, logMsg);
		break;
	case Service_OutofLogin:
		strcpy(message, OUTOF_LOGIN);
		strcpy(reason, REASON_ERROR);
		Send(reason, message);
		sprintf(logMsg, "User %s %s", m_User.username.c_str(), OUTOF_LOGIN);
		userLog.Get(logINFO, logMsg);
		break;
	case Service_Ok:
		strcpy(message, USER_VERIFY);
		strcpy(reason, REASON_NOTIFY);
		Send(reason, message);
		

		/* Send expired day */
		strcpy(message, m_User.expiryDate.c_str());
		strcpy(reason, REASON_EXPIREDDATE);
		Send(reason, message);

		/* Send product list*/
		strcpy(message, m_User.product.c_str());
		strcpy(reason, REASON_PRODUCT_LIST);
		Send(reason, message);

		/* Reset loginAttmp to 0 */
		m_Db.m_Subcribers.UpdateLoginAttempts(m_User.username, 0);
		m_Db.Save();

		sprintf(logMsg, "User %s %s", m_User.username.c_str(), USER_VERIFY);
		userLog.Get(logINFO, logMsg);
		break;
	}
	
}
