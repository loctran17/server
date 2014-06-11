#include "CProducts.h"

using namespace std;
using namespace boost;
using namespace boost::property_tree;



CProducts::CProducts()
{
	dataBaseFile = (char*)("/root/Server/database.dat");
}

CProducts::CProducts(const char		*dataBasePath)
{
	dataBaseFile = (char*)dataBasePath;
}

CProducts::~CProducts()
{
}

/* Save/Load Method */
void CProducts::Load()
{
	// populate tree structure pt
	using boost::property_tree::ptree;
	ptree pt;
	std::ifstream is(dataBaseFile);
	std::string vac_string(Product_VAC);
	std::string league_string(Product_League);

	/* Remove all memeber first */
	products.clear();

	read_xml(is, pt);

	// traverse pt
	BOOST_FOREACH(ptree::value_type const&v, pt.get_child("database.products")) {
		if (v.first == "product") {
			Product prod;
			prod.productname = boost::to_lower_copy(v.second.get<std::string>("<xmlattr>.productname"));
			prod.game = v.second.get<std::string>("game");
			prod.build = v.second.get<std::string>("build");
			prod.driver = v.second.get<std::string>("driver");
			BOOST_FOREACH(ptree::value_type const&u, pt.get_child("database.products.product")) {
				if (u.first == "status")
				{
					
					if (prod.productname.compare(boost::to_lower_copy(vac_string)) == 0)
					{
						prod.status.VAC = u.second.get<std::string>("VAC");
					}
					else if (prod.productname.compare(boost::to_lower_copy(league_string)) == 0)
					{
						prod.status.VAC = u.second.get<std::string>("VAC");
						prod.status.ESL = u.second.get<std::string>("ESL");
						prod.status.ESEA = u.second.get<std::string>("ESEA");
					}
				}
			}
			products.push_back(prod);
		}
	}
}


/* Get product list */
std::vector <Product> CProducts::GetProductList()
{
	return products;
}

/* Get product from productname */
Product	CProducts::GetProduct(std::string productname)
{
	// username+SHA256(pass)+SHA256(HWID)
	Product prod;
	prod.productname = "anonymous";

	Load();

	BOOST_FOREACH(Product prod1, products)
	{
		if (prod1.productname.compare(boost::to_lower_copy(productname)) == 0)
		{
			return prod1;
		}
	}
	
	return prod;
}

/* Check a product is exist or not */
bool	CProducts::CheckProductExist(std::string productname)
{
	Load();

	BOOST_FOREACH(Product prod, products)
	{
		if (prod.productname.compare(boost::to_lower_copy(productname)) == 0)
			return true;
	}
	return false;
}

/* Update a product */
void	CProducts::UpdateProduct(std::string productname, std::string game, std::string build, std::string driver, ProductStatus status)
{
	int idx = 0;
	Product	prod;

	BOOST_FOREACH(prod, products) {
		if (prod.productname.compare(boost::to_lower_copy(productname)) == 0) {
			break;
		}
		idx = idx + 1;
	}
	prod.game = game;
	prod.build = build;
	prod.driver = driver;
	prod.status = status;
	products.at(idx) = prod;
	
}

/* Set database file name */
void CProducts::SetDatabasePath(char		*dataBasePath)
{
	dataBaseFile = dataBasePath;
}
