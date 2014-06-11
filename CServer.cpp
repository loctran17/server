#include "Includes.h"
#include "CService.h"
#include "CServer.h"

#if defined(WIN32)
#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x)   (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x)    WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)  ReleaseMutex(x)
#define THREAD_ID        GetCurrentThreadId()
#elif defined(_POSIX_THREADS)
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()
#else
#error You must define mutex operations appropriate for your platform!
#endif

int THREAD_setup(void);
int THREAD_cleanup(void);

static MUTEX_TYPE *mutex_buf = NULL;
extern CDateTime sched;
extern CLog		 userLog;

static void locking_function(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

int THREAD_setup(void)
{
	int i;

	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int THREAD_cleanup(void)
{
	int i;

	if (!mutex_buf)
		return 0;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

void handle_error(const char *file, int lineno, const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL(void)
{
	if (!THREAD_setup() || !SSL_library_init())
	{
		userLog.Get(logERROR, "[-] OpenSSL initialization or thread setup failed");
		exit(-1);
	}
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
}




void do_server_loop(CService *service)
{
	ServiceReturn	ret = service->CheckUser(); 
	char logMsg[256];
	
	service->ErrorHandle(ret);
	
	if (ret == Service_Ok)
	{
		char msgData[DATA_LENGTH];
		char msgReason[REASON_LENGTH];
		char product[DATA_LENGTH];

		char *msg = strdup(service->m_User.product.c_str());
		char *str1, *token;
		char *saveptr1;
		int j;

		for (j = 1, str1 = msg;; j++, str1 = NULL) {
			token = strtok_r(str1, ",\"", &saveptr1);
			if (token == NULL)
				break;
			else
			{
				strcpy(product, token);
				std::string productname(token);
				if (service->m_Db.m_Products.CheckProductExist(productname))
				{
					Product prod = service->m_Db.m_Products.GetProduct(productname);

					/* Send product to client */
					strcpy(msgData, product);
					strcpy(msgReason, REASON_PRODUCTNAME);
					service->Send(msgReason, msgData);
					strcpy(msgData, prod.game.c_str());
					strcpy(msgReason, REASON_PRODUCTGAME);
					service->Send(msgReason, msgData);
					strcpy(msgData, prod.build.c_str());
					strcpy(msgReason, REASON_PRODUCTBUILD);
					service->Send(msgReason, msgData);
					std::string vac_string(Product_VAC);
					std::string league_string(Product_League);
					if (prod.productname.compare(boost::to_lower_copy(vac_string)) == 0)
					{
						strcpy(msgData, prod.status.VAC.c_str());
						strcpy(msgReason, REASON_PRODUCTSTATVAC);
						service->Send(msgReason, msgData);
					}
					else if (prod.productname.compare(boost::to_lower_copy(league_string)) == 0)
					{
						strcpy(msgData, prod.status.VAC.c_str());
						strcpy(msgReason, REASON_PRODUCTSTATVAC);
						service->Send(msgReason, msgData);
						strcpy(msgData, prod.status.ESL.c_str());
						strcpy(msgReason, REASON_PRODUCTSTATESL);
						service->Send(msgReason, msgData);
						strcpy(msgData, prod.status.ESEA.c_str());
						strcpy(msgReason, REASON_PRODUCTSTATESEA);
						service->Send(msgReason, msgData);
					}
				}
			}
		}
		
		/* Send driver first */
		memset(msgReason, 0, sizeof(msgReason));
		memset(msgData, 0, sizeof(msgData));
		service->Recv(msgReason, msgData);
		if (strcmp(msgReason, REASON_PRODUCT) == 0)
		{
			char fileName[256];
			std::string productReceived("Pseudontech ");
			productReceived.append(msgData);
			Product p = service->m_Db.m_Products.GetProduct(productReceived);
			strcpy(fileName, "/root/Server/");
			strcat(fileName, p.driver.c_str());
			if (service->OpenDriver(fileName))
			{
				sprintf(logMsg, "User %s [+] Streaming Driver... ", service->m_User.username.c_str());
				userLog.Get(logINFO, logMsg);
				service->SendDriver(fileName);
			}

			strcpy(fileName, "/root/Server/");
			strcat(fileName, msgData);
			strcat(fileName, ".exe");
			if (service->OpenBinary(fileName))
			{
				sprintf(logMsg, "User %s [+] Streaming Binary... ", service->m_User.username.c_str());
				userLog.Get(logINFO, logMsg);
				service->SendBinary(fileName);
			}
		}
	}
	else
	{
		if (service->m_User.loginAttempts == MAX_LOGIN)
		{
			/* Registry timer and start timer: 1min */
			TimerHandler *timerHdl = new TimerHandler;
			sched.SetExpirationTime(timerHdl, 60);
			sched.SetUser(timerHdl, service->m_User);
			sched.SetDb(timerHdl, service->m_Db);
			sched.Register(timerHdl);
		}

	}
	
	delete service;
}

// Callback for verify function
int verify_callback(int ok, X509_STORE_CTX *store)
{
	if (!ok)
	{
#if 0
		char data[256];
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int  depth = X509_STORE_CTX_get_error_depth(store);
		int  err = X509_STORE_CTX_get_error(store);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
#endif
	}

	return ok;
}

// Client authentication
long post_connection_check(SSL *ssl)
{
	X509      *cert;
	X509_NAME *subj;
	char      data[256];
	int       extcount;
	int       ok = 0;
	
	if (!(cert = SSL_get_peer_certificate(ssl)))
		goto err_occured;
	if ((extcount = X509_get_ext_count(cert)) > 0)
	{
		int i;
		for (i = 0; i < extcount; i++)
		{
			X509_EXTENSION    *ext = X509_get_ext(cert, i);
			const char        *extstr = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));

			if (!strcmp(extstr, "subjectAltName"))
			{
				int                  j;
				unsigned char        *data;
				STACK_OF(CONF_VALUE) *val;
				CONF_VALUE           *nval;
				const X509V3_EXT_METHOD    *meth = X509V3_EXT_get(ext);

				if (!meth)
					break;
				data = ext->value->data;

				val = meth->i2v(meth,
				meth->d2i(NULL, (const unsigned char**)(&data), ext->value->length), NULL);
				for (j = 0; j < sk_CONF_VALUE_num(val); j++)
				{
					nval = sk_CONF_VALUE_value(val, j);
					if (!strcmp(nval->name, "DNS"))
					{
						ok = 1;
						break;
					}
				}
			}
			if (ok)
				break;
		}
	}

	if (!ok && (subj = X509_get_subject_name(cert)) && X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
	{
		
	}

	X509_free(cert);
	return SSL_get_verify_result(ssl);

err_occured:
	if (cert)
		X509_free(cert);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

void* server_thread(void *arg)
{
	CService *service = reinterpret_cast<CService*>(arg);
	do_server_loop(service);
	ERR_remove_state(0);
	return NULL;
}

CServer::CServer()
{
	m_ctx = NULL;
	m_acc = NULL;
}

CServer::CServer(const char* databasePath)
{
	m_ctx = NULL;
	m_acc = NULL;
	m_dataPath = databasePath;
}

CServer::~CServer()
{

}

bool CServer::Start(int iPort)
{
	char host[33];

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *method;
#else
	SSL_METHOD *method;
#endif
	
	init_OpenSSL();
	
	method = SSLv3_server_method();

	if (method == 0)
	{
		userLog.Get(logERROR, "[-] CServer::Start: SSLv3_server_method() failed");
		return false;
	}

	m_ctx = SSL_CTX_new(method);
	if (m_ctx == 0)
	{
		userLog.Get(logERROR, "[-] CServer::Start: SSL_CTX_new() failed");
		return false;
	}

	// BIO socket
	snprintf(host, sizeof(host), "%d", iPort);
	m_acc = BIO_new_accept((char*)host);
	if (!m_acc)
		userLog.Get(logERROR, "[-] CServer::Start: BIO_new_accept (creating server socket) failed");
	if (BIO_do_accept(m_acc) <= 0)
		userLog.Get(logERROR, "[-] CServer::Start: BIO_do_accept (binding server socket) failed");

	return true;
}

const static char* pass = "5a$9Z;7X2d" ;
static int password_cb(char *buf, int num, int rwflag, void *userdata);

// The password code is not thread safe
static int password_cb(char *buf, int num,
	int rwflag, void *userdata)
{
	if (num < (int)(strlen(pass)) + 1)
		return(0);

	strcpy(buf, pass);

	return(strlen(pass));
}

bool CServer::LoadCertificates(char* CertFile, char* KeyFile, char* CAFile)
{
	if (SSL_CTX_load_verify_locations(m_ctx, CAFile, NULL) != 1)
	{
		userLog.Get(logERROR, "[-] CServer::LoadCertificates: SSL_CTX_load_verify_locations failed");
		return false;
	}

	if (SSL_CTX_set_default_verify_paths(m_ctx) != 1)
	{
		userLog.Get(logERROR, "[-] CServer::LoadCertificates: SSL_CTX_set_default_verify_paths failed");
		return false;
	}

	// Load server certificate into the SSL context
	if (SSL_CTX_use_certificate_file(m_ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		userLog.Get(logERROR, "[-] CServer::Start: SSL_CTX_use_certificate_file failed");
		return false;
	}

	SSL_CTX_set_default_passwd_cb(m_ctx, password_cb);

	// Load the server private-key into the SSL context
	if (SSL_CTX_use_PrivateKey_file(m_ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		userLog.Get(logERROR, "[-] CServer::Start: SSL_CTX_use_PrivateKey_file failed");
		return false;
	}

	if (!SSL_CTX_check_private_key(m_ctx))
	{
		userLog.Get(logERROR, "[-] CServer::Start: SSL_CTX_check_private_key failed");
		return false;
	}

	SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(m_ctx, 4);

	return true;
}

bool CServer::Run()
{
	BIO	*client;
	SSL	*ssl;
	CService *service;
	CSslConnection *sslCon;
	THREAD_TYPE	tid;

	long error;

	while (1)
	{
		if (BIO_do_accept(m_acc) <= 0)
			userLog.Get(logERROR, "[-] CServer::Run: BIO_do_accept (accepting connection) failed");

		client = BIO_pop(m_acc);

		ssl = SSL_new(m_ctx);

		if (ssl == 0)
		{
			userLog.Get(logERROR, "[-] CServer::Run SSL_new failed");
			return false;
		}
		SSL_set_accept_state(ssl);
		SSL_set_bio(ssl, client, client);

		if (SSL_accept(ssl) <= 0)
			userLog.Get(logERROR, "[-] CServer::Run Error accepting SSL connection");

		// Client authentication
		if ((error = post_connection_check(ssl)) != X509_V_OK)
		{
			userLog.Get(logERROR, "[-] CServer::Run Error with client certificate ");
			return false;
		}

		// Create thread
		sslCon = new CSslConnection(ssl);
		service = new CService(sslCon, m_dataPath);
		THREAD_CREATE(tid, server_thread, service);
		
	}

	return true;
}

bool CServer::Stop()
{
	return true;
}


