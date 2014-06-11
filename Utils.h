#ifndef UTILS_H_
#define UTILS_H_

#include "Includes.h"

#define VERSION_LENGTH 	20

struct User
{
    std::string  username;
    std::string  password;
    std::string  HWID;
    std::string  expiryDate;
    int			 product;
    std::string  comment;
	std::string  version;
};

static inline void loadbar(unsigned int x, unsigned int n, unsigned int w = 50)
{
	if ((x != n) && (x % (n / 100) != 0))
		return;

	float ratio = x / (float)n;
	int   c = (int)(ratio * w);

	std::cout << std::setw(3) << (int)(ratio * 100) << "% [";

	for (int x = 0; x<c; x++)
	{
		std::cout << "=";
	}

	for (int x = c; x < (int)w; x++)
	{
		std::cout << " ";
	}

	std::cout << "]\r" << std::flush ;
}

#endif
