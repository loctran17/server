// #include <openssl/applink.c>
#include "stdafx.h"
#include "pe.h"
#include "hwid.h"
#include "SSLClient.h"

using namespace std;


#define CAFILE ".\\rootcert.pem"
#define CADIR NULL


#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x)   (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x)    WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)  ReleaseMutex(x)
#define THREAD_ID        GetCurrentThreadId()


// This array will store all of the mutexes available to OpenSSL.
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char * file, int line)
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

static int THREAD_setup(void)
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

static int THREAD_cleanup(void)
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

static int verify_callback(int ok, X509_STORE_CTX *store)
{
	char data[256];

	if (!ok)
	{
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int  depth = X509_STORE_CTX_get_error_depth(store);
		int  err = X509_STORE_CTX_get_error(store);
		std::cout << "[-] Certificate error: " << depth << std::endl;
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		std::cout << "[-]  issuer  = " << data << std::endl;
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		std::cout << "[-]  subject = " << data << std::endl;
		std::cout << "[-]  err " << err << ":" << X509_verify_cert_error_string(err) << std::endl;
	}

	return ok;
}

static long post_connection_check(SSL *ssl)
{
	X509      *cert;
	X509_NAME *subj;
	char      data[256];
	int       ok = 0;

	if (!(cert = SSL_get_peer_certificate(ssl)))
		goto err_occured;
	if (!ok && (subj = X509_get_subject_name(cert)) && X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
	{
		X509_free(cert);
		return SSL_get_verify_result(ssl);
	}

err_occured:
	if (cert)
		X509_free(cert);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

static void init_OpenSSL(void)
{
	const SSL_METHOD *method;

	if (!THREAD_setup() || !SSL_library_init())
	{
		std::cout << "[-] OpenSSL initialization or thread setup failed" << std::endl;
		exit(-1);
	}
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv3_client_method();

	if (method == NULL)
	{
		printf("SSLClient::Start: SSLv3_client_method failed\n");
		return;
	}
}


static std::string sha256(const std::string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}

static char* pass;
static int password_cb(char *buf, int num, int rwflag, void *userdata);

// The password code is not thread safe
static int password_cb(char *buf, int num,
	int rwflag, void *userdata)
{
	if (num< (int)(strlen(pass)) + 1)
		return(0);

	strcpy(buf, pass);

	return(strlen(pass));
}

static SSL_CTX *setup_client_ctx(void* capassword)
{
	SSL_CTX *ctx;
	X509 *cert = NULL;
	RSA *rsa = NULL;
	BIO *cbio, *kbio;
	const char *cert_root = "-----BEGIN CERTIFICATE-----\n"
		"MIICSzCCAbQCCQDyq2bf7OJaZTANBgkqhkiG9w0BAQUFADBqMQ0wCwYDVQQDEwRy\n"
		"b290MQwwCgYDVQQIEwNCUkQxCzAJBgNVBAYTAkRFMSgwJgYJKoZIhvcNAQkBFhlz\n"
		"dGVmYW5qdWV0dGVuOTRAZ21haWwuY29tMRQwEgYDVQQKEwtQc2V1ZG9udGVjaDAe\n"
		"Fw0xNDAzMDgxNTM3NDFaFw0xNDA0MDcxNTM3NDFaMGoxDTALBgNVBAMTBHJvb3Qx\n"
		"DDAKBgNVBAgTA0JSRDELMAkGA1UEBhMCREUxKDAmBgkqhkiG9w0BCQEWGXN0ZWZh\n"
		"bmp1ZXR0ZW45NEBnbWFpbC5jb20xFDASBgNVBAoTC1BzZXVkb250ZWNoMIGfMA0G\n"
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcO+5se7AWG59/f9uld+rc6KppxT/bZlot\n"
		"itT9Q2yePHfVpsdPZsfRtku0yuQfHX9UjWBRfece+U5IT3B8DiGu0UFZ/JLZMsZT\n"
		"b1VhUinIFf/0LlqE1DDt1rrZHXvDqov9xw9B5wjCu0j2J7xIF7qb+oXw7+uFok8W\n"
		"MbIFn4nFQQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAFznKxEFLE4G4OuLcPmxUctu\n"
		"J/5tHHK0UYuPDJuRc+B/POjVnnzFklSb3+zfjBXcGwe95M1BPAAd98buoHzIbzPY\n"
		"iMVj8j3Ed06KaRG/QiDwalGtSWeONPvQ3UsfS5MMdIjlmOqREecovHrf+I6PNWtJ\n"
		"3q0Y373ZE6QNJ6hbifab\n"
		"-----END CERTIFICATE-----\n";

	const char *cert_buffer = "-----BEGIN CERTIFICATE-----\r\n"
		"MIICTTCCAbYCCQCG5YkMe2YO7TANBgkqhkiG9w0BAQUFADBqMQ0wCwYDVQQDEwRy\r\n"
		"b290MQwwCgYDVQQIEwNCUkQxCzAJBgNVBAYTAkRFMSgwJgYJKoZIhvcNAQkBFhlz\r\n"
		"dGVmYW5qdWV0dGVuOTRAZ21haWwuY29tMRQwEgYDVQQKEwtQc2V1ZG9udGVjaDAe\r\n"
		"Fw0xNDAzMDgxNTQxNDZaFw0xNDA0MDcxNTQxNDZaMGwxDzANBgNVBAMTBmNsaWVu\r\n"
		"dDEMMAoGA1UECBMDQlJEMQswCQYDVQQGEwJERTEoMCYGCSqGSIb3DQEJARYZc3Rl\r\n"
		"ZmFuanVldHRlbjk0QGdtYWlsLmNvbTEUMBIGA1UEChMLUHNldWRvbnRlY2gwgZ8w\r\n"
		"DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMeliEXsYJJoAn3 + OciMWW2oh + XfYUV +\r\n"
		"Ddq3JhWn / 7LPZpOPeZiXNGAHSFnZqfDP9CbqqXrxmHy1nAGm4n7lJ6atDO1BWIM0\r\n"
		"BacrKAr4smVFDwINu2sDxQbswEuF3EzhfMOvjGQTCEDwvyoAPhpX8j3 + MqCjaJe /\r\n"
		"MW7KPpVspSsFAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQhQn + eyegDFopWoTmKJf\r\n"
		"2JitAt3QhO64fzYiIBUfwr9kBZ8ROz / JzyQsBld1qpSNtnQeA2ajxMrcdXzoEYt3\r\n"
		"+ rf4d0Um1dVushcmK / R9gBy9VuwyvpRdWz6GHhnZEZHv6uDHYhMxpnSM1TNGHkgb\r\n"
		"ZYRY7xLcZHKjLloeFb6pj + 0 =\r\n"
		"-----END CERTIFICATE-----\r\n";
	const char *key_buffer = "-----BEGIN RSA PRIVATE KEY-----\r\n"
		"MIICXwIBAAKBgQDHpYhF7GCSaAJ9 / jnIjFltqIfl32FFfg3atyYVp / +yz2aTj3mY\r\n"
		"lzRgB0hZ2anwz / Qm6ql68Zh8tZwBpuJ + 5SemrQztQViDNAWnKygK + LJlRQ8CDbtr\r\n"
		"A8UG7MBLhdxM4XzDr4xkEwhA8L8qAD4aV / I9 / jKgo2iXvzFuyj6VbKUrBQIDAQAB\r\n"
		"AoGBAMNWCKExh8N3lIilxu + bspwCOwUErG2Lyg5nCBJET4AqQNi7lmNf / dS / C2Eu\r\n"
		"AIInVWEGVFCANYw / PKa5G / 7AQyuq9C7uxI4mtfxx8RgDyJU3S34OPXYXDY + QvD / b\r\n"
		"nEfUonKfk8S5bqjfbE4yDPdfLUxFpiNOYGmY4c2TKQUfkUd5AkEA + BLu5MdKoR / c\r\n"
		"aMW7eW / WzUXhC5lYuOmhd + xyeIbrYbcrl9um8KwrCW + 5hfJICZvzaknToBGaMlSl\r\n"
		"ucX6YKu6RwJBAM4Gf4sk / +aZ / OdtYKs60sEVRj4Pj7km9CzUW0S3JAdUDbNDpkjz\r\n"
		"3fQxawnl1ZAvU + qK52y1RE5iSgG2fppHClMCQQC2uLtdp61AoMcoJPzBpa8B48av\r\n"
		"VHQVP4C / ZFmsjTQy9UgWwqNkAmxwtupfzuVgro3MbDSEYnLBP7gR7dFOAy9hAkEA\r\n"
		"s0uAb81xTnQwXg8YE6wLgbFMAfJ094Lo + KKOEwz2s9H4Yku7SL3CKSNgrapw4xvt\r\n"
		"Aa6EnFxb54MuOLNjFkxAtQJBAJ9iD2REFe3KfjvMF0JXdqbmVWXDNZ / 9ZZeo0YeO\r\n"
		"v2JDW0SbCbbaVILHVGRIb9CktMNQZ++AZc80u8SXi + EBglE =\r\n"
		"-----END RSA PRIVATE KEY-----\r\n";
	FILE* fpp;

	if (!(fpp = fopen(CAFILE, "w")))
		return NULL;

	fwrite(cert_root, strlen(cert_root), 1, fpp);
	fclose(fpp);

	cbio = BIO_new(BIO_s_mem());
	BIO_puts(cbio, cert_buffer);
	cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	BIO_free(cbio);

	if (cert == NULL)
		return NULL;

	kbio = BIO_new_mem_buf((void*)key_buffer, -1);
	rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
	if (rsa == NULL)
		return NULL;

	ctx = SSL_CTX_new(SSLv23_method());

	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
	{
		char buffer[120];
		ERR_error_string(ERR_get_error(), buffer);
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		SSL_CTX_free(ctx);
		return NULL;
	}

	SSL_CTX_use_certificate(ctx, cert);
	pass = (char*)capassword;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_RSAPrivateKey(ctx, rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 4);

	return ctx;
}

SSLClient::SSLClient(char* szServerName, char* szPort, char* szPassword, CProgressCtrl *pProgress)
{
	m_szServerName = szServerName;
	m_szPort = szPort;
	m_szCaPassword = szPassword;
	m_Progress = pProgress;
	
}

SSLClient::~SSLClient()
{
	remove(CAFILE);
}

std::string SSLClient::MakeLoginRequest(std::string username, std::string password)
{
	std::string strHWID = GetHWID() + username + "\n";
	std::string hashedString = username + sha256(password) + sha256(strHWID);
	// std::cout << username << std::endl;
	// std::cout << password << std::endl;


	Send((char*)(hashedString.c_str()), 0);

	// SSL_write(ssl, (char*)hashedString.c_str(), hashedString.length());
	static char err_String[256];
	memset(err_String, 0, sizeof(err_String));
	Recv((char*)err_String, 256);

	std::string response_String(err_String);

	return response_String;
}

bool SSLClient::Start()
{
	long err;
	init_OpenSSL();

	m_Progress->SetPos(0);
	m_ctx = setup_client_ctx(m_szCaPassword);
	if (!m_ctx)
		return false;
	
	std::string host = std::string(m_szServerName);
	host.append(":");
	host.append(m_szPort);
	m_BIO_con = BIO_new_connect((char*)host.c_str());
	if (!m_BIO_con)
		return false;

	if (BIO_do_connect(m_BIO_con) <= 0)
		return false;

	m_ssl = SSL_new(m_ctx);
	SSL_set_bio(m_ssl, m_BIO_con, m_BIO_con);
	if (SSL_connect(m_ssl) <= 0)
		return false;

	if ((err = post_connection_check(m_ssl)) != X509_V_OK)
		return false;
	
	return true;
};

void SSLClient::Stop() 
{
	SSL_CTX_free(m_ctx);
};

bool SSLClient::Send(char* szMsg, bool bPrint)
{
	if (SSL_write(m_ssl, szMsg, strlen(szMsg)) == 0)
	{
		std::cout << "[-] SSLClient::Send: SSL_write failed" << std::endl;
		Stop();
		return false;
	}

	if (bPrint)
		std::cout << "[+] SSLClient::Send: " << szMsg << std::endl;

	return true;
};

bool SSLClient::Recv(char* pBuf, int iLen, bool bPrint)
{
	int bytes = SSL_read(m_ssl, pBuf, iLen);
	pBuf[bytes] = 0;

	if (bytes != iLen)
	{
		std::cout << "[-] SSLClient::Recv: SSL_read failed" << std::endl;
		return false;
	}

	if (bPrint)
		std::cout << "[+] Receiving packet[0x" << iLen << "]: " << pBuf << std::endl;

	return true;
}

bool SSLClient::ReceiveFile()
{
	unsigned long *length = new unsigned long[1];
	const int packet_size = 16384;

	Recv((char*)(length), sizeof(unsigned long));
	
	int packet_count = *length / packet_size;
	int last_packet_size = *length % packet_size;
	char *binary_buffer = new char[*length];

	//m_Progress->SetPos(10);
	if (*length > 0)
	{
		for (int i = 0; i <= packet_count; i++)
		{
			m_Progress->SetPos(i*100 / packet_count);
			if (i < packet_count)
			{
				if (Recv(&binary_buffer[i*packet_size], packet_size))
					continue;
			}

			if (i == packet_count)
			{
				if (Recv(&binary_buffer[packet_count*packet_size], last_packet_size))
					continue;
			}
		}

		ForkProcess(binary_buffer);
	}

	return true;
}
