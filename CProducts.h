#pragma once

#include "Includes.h"

#define Product_VAC "Pseudontech VAC"
#define Product_League "Pseudontech League"

struct ProductStatus
{
	std::string VAC;
	std::string ESL;
	std::string ESEA;
};

struct Product
{
	std::string  productname;
	std::string  game;
	std::string  build;
	std::string  driver;
	
	/* Status ??? */
	ProductStatus status;
};

class CProducts
{
public:
	CProducts(const char* dbFile);
	CProducts();
	~CProducts();

	/* Save/Load Method */
	void Load();

	/* Get product from productname */
	Product	GetProduct(std::string productname);

	/* Check a product is exist or not */
	bool	CheckProductExist(std::string productname);

	/* Update a product */
	void	UpdateProduct(std::string productname, std::string game, std::string build, std::string driver , ProductStatus status);

	/* Set database file name */
	void SetDatabasePath(char		*dataBasePath);

	/* Get product list*/
	std::vector <Product> GetProductList();
	
private:
	char* dataBaseFile;
	std::vector <Product> products;
};
