#ifndef COMMON_HPP
#define COMMON_HPP

#include <string>
#include <sstream>

typedef std::basic_string<unsigned char> ustring;
typedef std::basic_istream<unsigned char> uistream;
typedef std::basic_istringstream<unsigned char> uistringstream; // lmao
typedef std::basic_ostream<unsigned char> uostream;
typedef std::basic_ostringstream<unsigned char> uostringstream;

namespace std
{
	template<> struct hash<ustring>
	{
		// I'm sure this implementation is terrible
		std::size_t operator()(ustring const &str) const noexcept
		{
			constexpr int bits_m_1 = sizeof(std::size_t) * 8 - 1;
			std::size_t h = str.size() << 8;
			const unsigned char *p = &str[0];
			for(ustring::size_type i = 0; i < str.size(); i++) {
				h ^= p[i];
				h = (h << 1) | (h >> bits_m_1);
			}
			return h;
		}
	};
}

#endif // COMMON_HPP
