#ifndef CSUBSCRIBERS_H_
#define CSUBSCRIBERS_H_

#include "Includes.h"

using namespace std;
using namespace boost;
using namespace boost::property_tree;


typedef boost::gregorian::date Date;


struct User
{
	std::string  username;
	std::string  password;
	std::string  HWID;
	std::string  expiryDate;
	std::string	 product;
	std::string  comment;
	std::string  version;
	unsigned int loginAttempts;
};

typedef std::vector<User> Subscribers;

class CSubscribers
{
public:
	CSubscribers(const char* dbPath);
	CSubscribers();
	virtual ~CSubscribers();
	
	void Load();
	void Save();
	
	// Register a user from file
	void AddUser(std::istream & is);
	
	// Check user exist in database
	bool CheckExistUser(User v);
	
	// Get specific user
	User GetUser(std::string userName);
	
	// Update user
	void Update(std::string username, std::string password, std::string HWID, std::string comment, std::string version);
	void UpdateLoginAttempts(std::string username, unsigned int loginAttempts);
	void SetDatabasePath(char		*dataBasePath);

	/* Get user list */
	std::vector<User> GetUserList();
	
private:	
	Subscribers	sub;
	char		*dataBasePath; 
};

#endif
