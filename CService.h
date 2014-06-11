#ifndef CSERVICE_H_
#define CSERVICE_H_

#include "CLog.h"
#include "CSslConnection.h"
#include "CDb.h"

/* Message will send to client */
#define USER_NOT_REG	"[-] You have to be a subscriber to use our products"
#define WRONG_PASS		"[-] Wrong password, please try again"
#define EXP_DAY			"[-] Your subscription expired"
#define OLD_VERSION		"[-] Please download an updated version of this software"
#define USER_VERIFY		"[+] Login successful"
#define OUTOF_LOGIN		"[-] Too many failed login attempts, try again in 1 minute"


/* Reasons */
#define REASON_USERNAME			"Username"
#define REASON_HWID				"HWID"
#define REASON_VERSION			"Version"
#define REASON_EXPIREDDATE		"Expireddate"
#define REASON_ERROR			"Error"
#define REASON_NOTIFY			"Notification"
#define REASON_PRODUCT_LIST		"ProductList"
#define REASON_PRODUCTNAME		"Productname"
#define REASON_PRODUCTGAME		"Game"
#define REASON_PRODUCTBUILD		"Build"
#define REASON_PRODUCT			"Product"

/* Product status */
#define REASON_PRODUCTSTATVAC	"VAC"
#define REASON_PRODUCTSTATESL	"ESL"
#define REASON_PRODUCTSTATESEA	"ESEA"

/* Maximum number of login */
#define MAX_LOGIN		3

/* Reason length  */
#define REASON_LENGTH	64

/* Data lenght */
#define DATA_LENGTH		128

typedef enum ServiceReturn
{
	Service_UserNotRegister,
	Service_WrongPassword,
	Service_ExpiredDay,
	Service_OldVersion,
	Service_OutofLogin,
	Service_Ok
} ServiceReturn;

class CService {
public:
	CService(CSslConnection *conn);
	CService(CSslConnection *conn, const char* dbPath);
	virtual ~CService();

	ServiceReturn CheckUser();
	bool OpenBinary(const char* szBinary);
	bool SendBinary(const char* szBinary, const bool bPrintProgress = 1);
	bool OpenDriver(const char* szBinary);
	bool SendDriver(const char* szBinary, const bool bPrintProgress = 1);
	void ErrorHandle(ServiceReturn ret);
	void Send(char* reason, char* pBuf);
	void Recv(char* reason, char* pBuf);
	User 			m_User;
	CDb				m_Db;
	
private:
	// SSL Connection of this service
	CSslConnection	*m_con;
	CLog			userLog;
	
};

#endif
