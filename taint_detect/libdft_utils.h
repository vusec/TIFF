#ifndef __LIBDFT_UTILS_H__
#define __LIBDFT_UTILS_H__

#include <string>
#include <vector>

struct UINT256_T{
	unsigned long d[4];

	bool operator==(const UINT256_T& a) const
	{
		return (d[0] == a.d[0])&&(d[1] == a.d[1])&&(d[2] == a.d[2])&&(d[3] == a.d[3]);
	}
	
	bool operator<(const UINT256_T& a) const
	{
		if (d[0] < a.d[0])
			return true;
		else if (d[0] > a.d[0])
			return false;
		if (d[1] < a.d[1])
			return true;
		else if (d[1] > a.d[1])
			return false;
		if (d[2] < a.d[2])
			return true;
		else if (d[2] > a.d[2])
			return false;
		if (d[3] < a.d[3])
			return true;
		else if (d[3] > a.d[3])
			return false;
		return false;
	}

	UINT256_T& operator=(const UINT256_T& a)
	{
		d[0] = a.d[0];
		d[1] = a.d[1];
		d[2] = a.d[2];
		d[3] = a.d[3];
		return *this;
	}
};

/* Greatest common divisor. 
 * If val1 and val2 <= GCD_MAX (16), precomputed results are used. 
 * Otherwise binary gcd algorithm is applied. 
 */
int gcd(int val1, int val2); 

void SplitString(const std::string& s, std::vector<std::string>& v, const std::string& c);

//#define USE_SSE
//#define DISABLE_SSE

#ifdef DISABLE_SSE
	#ifdef USE_SSE
		#undef USE_SSE
	#endif
#endif

//#define min(X,Y) ((X) < (Y) ? (X) : (Y))
//#define max(X,Y) ((X) > (Y) ? (X) : (Y))

/* x \in [a, b] */
#define inbetween_inclusive(x, a, b)    ((x >= a) && (x <= b)) 
/* x \in (a, b) */
#define inbetween_exclusive(x, a, b)    ((x > a) && (x < b))


#endif
