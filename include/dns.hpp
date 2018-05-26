#ifndef DNS_HPP
#define DNS_HPP

#include <stdint.h>
#include <netinet/in.h>
#include <exception>
#include <vector>

#include "common.hpp"

class DecodeException : public std::exception {
public:
	DecodeException(const char *file, int line, const char *func);
	const char* what() const noexcept { return text.c_str(); };

private:
	std::string text;
};

/*
	https://tools.ietf.org/html/rfc1035 General
	https://tools.ietf.org/html/rfc3596 IPv6 types
*/

struct DNSName {
	std::vector<std::string> labels;

	void encode(uostream &s) const;
	void decode(uistream &s, const ustring &whole_pkt, bool can_recurse=true);

	std::string toString() const;
	void parse(const std::string &s);
};

enum DNSType {
	DNS_TYPE_A = 1, // a host address
	DNS_TYPE_NS = 2, // an authoritative name server
	DNS_TYPE_CNAME = 5, // the canonical name for an alias
	DNS_TYPE_SOA = 6, // marks the start of a zone of authority
	DNS_TYPE_PTR = 12, // a domain name pointer
	DNS_TYPE_MX = 15, // mail exchange
	DNS_TYPE_TXT = 16, // text strings
	DNS_TYPE_AAAA = 28, // a single IPv6 address

	DNS_QTYPE_AXFR = 252, // A request for a transfer of an entire zone
	DNS_QTYPE_ANY = 255, // A request for all records
};

enum DNSClass {
	DNS_CLASS_IN = 1, // the Internet
	DNS_CLASS_CH = 3, // the CHAOS class
	DNS_CLASS_HS = 4, // Hesiod [Dyer 87]

	DNS_QCLASS_ANY = 255, // any class
};

struct DNSQuestion {
	DNSName name;
	enum DNSType qtype;
	enum DNSClass qclass;

	void encode(uostream &s) const;
	void decode(uistream &s, const ustring &whole_pkt);

	void parse(const std::string &s);
};

struct DNSAnswer {
	DNSName name;
	enum DNSType type;
	enum DNSClass class_;
	int32_t ttl;
	struct {
		union {
			struct in_addr addr4; // A
			struct in6_addr addr6; // AAAA
		};
		DNSName name; // NS, CNAME, PTR
	} rdata;

	void decode(uistream &s, const ustring &whole_pkt);

	std::string toString() const;
};

struct DNSPacket {
	uint16_t txid;
	uint16_t flags;
	std::vector<DNSQuestion> questions;
	std::vector<DNSAnswer> answers;

	void encode(ustring *data) const;
	void decode(const ustring &data);
};

#endif // DNS_HPP
