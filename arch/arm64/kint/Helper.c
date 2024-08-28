#include "kint.h"

void __hyp_text *el2_bsearch(const void *key, const void *base, size_t num, size_t size,
	      int (*cmp)(const void *key, const void *elt))
{
	const char *pivot;
	int result;
	u64 cnt = 0;

	while (num > 0) {
		
		pivot = base + (num >> 1) * size;
		result = cmp(key, pivot);

		if (result == 0)
			return (void *)pivot;

		if (result > 0) {
			base = pivot + size;
			num--;
		}
		num >>= 1;
		cnt++; 
	}
	return NULL;
}

u64 __hyp_text el2_strcmp(const char *s1, const char *s2)
{
    while(*s2 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

u64 __hyp_text el2_strncmp(const char *s1, const char *s2, u32 n)
{
    while(n && *s2 && (*s1 == *s2))
    {
        s1++;
        s2++;
		n--;
    }
	if(n == 0)
		return 0;

    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

u64 __hyp_text el2_strlen(const char *str)
{
        const char *s;

        for (s = str; *s; ++s)
                ;
        return (s - str);
}

char * __hyp_text el2_next_str(char *string, u64 *secsize)
{
	/* Skip non-zero chars */
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}

	/* Skip any zero padding. */
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	return string;
}

char*  __hyp_text el2_strncpy(char* dest, const char* source, u32 num)
{	
    if (dest == NULL) {
        return NULL;
    }

    char* ptr = dest;

    while (*source && num--)
    {
        *dest = *source;
        dest++;
        source++;
    }

    *dest = '\0';
 
    return ptr;
}
