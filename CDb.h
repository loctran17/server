#pragma once

#include "Includes.h"
#include "CSubscribers.h"
#include "CProducts.h"

class CDb
{
public:
	CDb();
	~CDb();
	CDb(const char* dbFileName);

	/* Load and Save function */
	void Load();
	void Save();

	/* Public attribute: Subcribers and Products */
	CSubscribers	m_Subcribers;
	CProducts		m_Products;

private:
	char*			m_dbFileName;
};

