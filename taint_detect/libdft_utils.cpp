#include <stdlib.h>
#include <stdint.h>
#include <assert.h> 
#include <string>
#include <vector>

#include "libdft_utils.h"

#define GCD_MAX     16

static const int gcd_table[GCD_MAX + 1][GCD_MAX + 1] = {
/*  0 */    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0},  
/*  1 */    {0, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1,  1,  1,  1,  1,  1,  1},
/*  2 */    {0, 1, 2, 1, 2, 1, 2, 1, 2, 1,  2,  1,  2,  1,  2,  1,  2},
/*  3 */    {0, 1, 1, 3, 1, 1, 3, 1, 1, 3,  1,  1,  3,  1,  1,  3,  1},
/*  4 */    {0, 1, 2, 1, 4, 1, 2, 1, 4, 1,  2,  1,  4,  1,  2,  1,  4},
/*  5 */    {0, 1, 1, 1, 1, 5, 1, 1, 1, 1,  5,  1,  1,  1,  1,  5,  1},
/*  6 */    {0, 1, 2, 3, 2, 1, 6, 1, 2, 3,  2,  1,  6,  1,  2,  3,  2},
/*  7 */    {0, 1, 1, 1, 1, 1, 1, 7, 1, 1,  1,  1,  1,  1,  7,  1,  1},
/*  8 */    {0, 1, 2, 1, 4, 1, 2, 1, 8, 1,  2,  1,  4,  1,  2,  1,  8},
/*  9 */    {0, 1, 1, 3, 1, 1, 3, 1, 1, 9,  1,  1,  3,  1,  1,  3,  1},
/* 10 */    {0, 1, 2, 1, 1, 5, 1, 1, 1, 1, 10,  1,  2,  1,  1,  5,  2},
/* 11 */    {0, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, 11,  1,  1,  1,  1,  1},
/* 12 */    {0, 1, 2, 3, 4, 1, 6, 1, 4, 3,  2,  1, 12,  1,  2,  3,  4},  
/* 13 */    {0, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1,  1,  1, 13,  1,  1,  1}, 
/* 14 */    {0, 1, 2, 1, 1, 1, 1, 7, 1, 1,  1,  1,  1,  1, 14,  1,  2},
/* 15 */    {0, 1, 1, 3, 1, 5, 1, 1, 1, 3,  1,  1,  3,  1,  1, 15,  1},
/* 16 */    {0, 1, 2, 1, 4, 1, 2, 1, 8, 1,  2,  1,  4,  1,  2,  1, 16}  
    };

/* the binary gcd algorithm, aka Stein's algorithm */
static uint32_t
gcd_binary(uint32_t u, uint32_t v)
{
    int shift;

    /* GCD(0,x) := 0 */
    if (u == 0 || v == 0)
        return 0;

    /* Let shift := lg K, where K is the greatest power of 2 dividing both u and v. */
    for (shift = 0; ((u | v) & 1) == 0; ++shift) {
        u >>= 1;
        v >>= 1; 
    }  

    while ((u & 1) == 0)
        u >>= 1;  

    /* From now on, u is always odd. */ 
    do {
        while ((v & 1) == 0)
            v >>= 1;
        
        /*  Now u and v are both odd, so diff(u, v) is even. 
            Let u = min(u, v), v = diff(u, v)/2. 
         */  
        if (u < v) {
            v -= u;
        } else {
            uint32_t diff = u - v;
            u = v;
            v = diff; 
        }
        v >>= 1; 
    } while (v != 0); 

    return u << shift;
}

/* Greatest common divisor. 
 * If u and v <= GCD_MAX (16), precomputed results are used. 
 * Otherwise binary gcd algorithm is applied. 
 */
int 
gcd(int u, int v)
{
	if (u <=0)
		return v;
	else if (v<=0)
		return u;

    if ((u <= GCD_MAX) && (v <= GCD_MAX)) { 
        return gcd_table[u][v]; 
    } 
 
    return (uint32_t)gcd_binary((uint32_t)u, (uint32_t)v); 
}

void 
SplitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
  std::string::size_type pos1, pos2;
  pos2 = s.find(c);
  pos1 = 0;
  while(std::string::npos != pos2)
  {
    v.push_back(s.substr(pos1, pos2-pos1));
 
    pos1 = pos2 + c.size();
    pos2 = s.find(c, pos1);
  }
  if(pos1 != s.length())
    v.push_back(s.substr(pos1));
}
