#include "CDb.h"

using namespace std;
using namespace boost;
using namespace boost::property_tree;

CDb::CDb()
{
	/* Dedault database file */
	m_dbFileName = "/root/Server/database.dat";
	m_Subcribers = CSubscribers(m_dbFileName);
	m_Products = CProducts(m_dbFileName);
}

CDb::CDb(const char* dbFileName)
{
	m_Subcribers	= CSubscribers(dbFileName);
	m_Products = CProducts(dbFileName);
	m_dbFileName = (char*)dbFileName;
}


CDb::~CDb()
{
}

void CDb::Load()
{
	m_Subcribers.Load();
	m_Products.Load();
}

void CDb::Save()
{
	std::ofstream os(m_dbFileName, ios::trunc);
	using boost::property_tree::ptree;
	ptree dbTree;
	
	/* Subscribers tree */
	ptree &subscribersTree = dbTree.add("database.subscribers", "");

	/* Products tree */
	ptree & productTree = dbTree.add("database.products", "");

	/* Subscribers tree */
	std::vector <User> userList = m_Subcribers.GetUserList();
	

	BOOST_FOREACH(User u, userList)
	{
		ptree & node = subscribersTree.add("user", "");
		node.put("<xmlattr>.username", u.username);
		node.put("password", u.password);
		node.put("HWID", u.HWID);
		node.put("expiryDate", u.expiryDate);
		node.put("product", u.product);
		node.put("comment", u.comment);
		node.put("version", u.version);
		node.put("loginAttempts", u.loginAttempts);
	}
	
	/* Product tree */
	std::vector <Product> prodList = m_Products.GetProductList();

	BOOST_FOREACH(Product prod, prodList)
	{
		ptree & node = productTree.add("product", "");
		node.put("<xmlattr>.productname", prod.productname);
		node.put("game", prod.game);
		node.put("build", prod.build);
		node.put("driver", prod.driver);
		ptree & node_Child = node.add("status", "");
		std::string vac_string(Product_VAC);
		std::string league_string(Product_League);
		if (prod.productname.compare(boost::to_lower_copy(vac_string)) == 0)
		{
			node_Child.put("VAC", prod.status.VAC);
		}
		else if (prod.productname.compare(boost::to_lower_copy(league_string)) == 0)
		{
			node_Child.put("VAC", prod.status.VAC);
			node_Child.put("ESL", prod.status.ESL);
			node_Child.put("ESEA", prod.status.ESEA);
		}

	}
	
	write_xml(os, dbTree);
}

