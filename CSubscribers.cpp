#include "CSubscribers.h"

namespace bt = boost::posix_time;
const std::locale formats[] = {
	std::locale(std::locale::classic(), new bt::time_input_facet("%Y-%m-%d %H:%M:%S")),
	std::locale(std::locale::classic(), new bt::time_input_facet("%Y/%m/%d %H:%M:%S")),
	std::locale(std::locale::classic(), new bt::time_input_facet("%d.%m.%Y %H:%M:%S")),
	std::locale(std::locale::classic(), new bt::time_input_facet("%Y-%m-%d"))
};
const size_t formats_n = sizeof(formats) / sizeof(formats[0]);

static void trim(std::string& str, char c_trim)
{
	std::string::size_type pos = str.find_last_not_of(c_trim);
	if (pos != std::string::npos) {
		str.erase(pos + 1);
		pos = str.find_first_not_of(c_trim);
		if (pos != std::string::npos) str.erase(0, pos);
	}
	else str.erase(str.begin(), str.end());
}

std::time_t pt_to_time_t(const bt::ptime& pt)
{
	bt::ptime timet_start(boost::gregorian::date(1970, 1, 1));
	bt::time_duration diff = pt - timet_start;
	return diff.ticks() / bt::time_duration::rep_type::ticks_per_second;
}

CSubscribers::CSubscribers(const char *dbPath)
{
	dataBasePath = (char*)dbPath;
	
}

CSubscribers::CSubscribers()
{
	dataBasePath = (char*)("/root/Server/database.dat");
}


CSubscribers::~CSubscribers()
{

}

void CSubscribers::Load()
{
	// populate tree structure pt
	using boost::property_tree::ptree;
	ptree pt;

	std::ifstream is(dataBasePath);

	sub.clear();

	read_xml(is, pt);
	
	// traverse pt
	BOOST_FOREACH( ptree::value_type const&v, pt.get_child("database.subscribers") ) {
		if( v.first == "user" ) {
			User u;
			u.username = v.second.get<std::string>("<xmlattr>.username");
			u.password = v.second.get<std::string>("password");
			u.HWID = v.second.get<std::string>("HWID");
			u.expiryDate = v.second.get<std::string>("expiryDate"); 
			u.product = v.second.get<std::string>("product");
			u.comment = v.second.get<std::string>("comment");
			u.version = v.second.get<std::string>("version");
			u.loginAttempts = v.second.get<unsigned int>("loginAttempts");
			sub.push_back(u);
		}
	}
}

void CSubscribers::Update(std::string username, std::string password, std::string HWID, std::string comment, std::string version)
{
	int idx = 0;
	User	u1;
	
	BOOST_FOREACH( u1, sub ) {
		if (u1.username.compare(username) == 0) {
			break;
		}
		idx = idx + 1;
	}
	u1.password = password;
	u1.HWID = HWID;
	u1.comment = comment;
	trim(version, ' ');
	u1.version = version;
	sub.at(idx) = u1;
	
	
}

void CSubscribers::UpdateLoginAttempts(std::string username, unsigned int loginAttempts)
{
	int idx = 0;
	User	u1;
	
	BOOST_FOREACH(u1, sub) {
		if (u1.username.compare(username) == 0) {
			break;
		}
		idx = idx + 1;
	}
	u1.loginAttempts = loginAttempts;
	sub.at(idx) = u1;
	
}

void CSubscribers::AddUser(std::istream &is)
{
	Load();
	
	// populate tree structure pt
	using boost::property_tree::ptree;
	ptree pt;
	
	read_xml(is, pt);
	
	// traverse pt
	BOOST_FOREACH( ptree::value_type const&v, pt) {
		if( v.first == "user" )
		{
			User u;
			u.username = v.second.get<std::string>("<xmlattr>.username");
			u.password = v.second.get<std::string>("password");
			u.HWID = v.second.get<std::string>("HWID");
			u.expiryDate = v.second.get<std::string>("expiryDate"); 
			u.product = v.second.get<std::string>("product");
			u.comment = v.second.get<std::string>("comment");
			u.version = v.second.get<std::string>("version");
			u.loginAttempts = v.second.get<unsigned int>("loginAttempts");
			if (!CheckExistUser(u)) sub.push_back(u);
		}
	}
}


std::vector<User> CSubscribers::GetUserList()
{
	return sub;
}

bool CSubscribers::CheckExistUser(User v)
{
	BOOST_FOREACH(User u, sub)
	{
		if (u.username.compare(v.username) == 0)
			return true;
	}
	return false;
}

User CSubscribers::GetUser(std::string userName)
{
	// username+SHA256(pass)+SHA256(HWID)
	User u;
	u.username = "anonymous";

	BOOST_FOREACH( User u1, sub )
	{
		if (u1.username.compare(userName) == 0)
			return u1;
	}
	return u;
}

void CSubscribers::SetDatabasePath(char *dbPath)
{
	dataBasePath = dbPath;
}