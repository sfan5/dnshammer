#include <endian.h>
#include <arpa/inet.h>
#include <sstream>

#include "dns.hpp"
#include "common.hpp"

#define DECODE_ASSERT(expr) do { \
	if(!(expr)) \
		throw DecodeException(__FILE__, __LINE__, __PRETTY_FUNCTION__); \
	} while(0)

static void writeU8(uostream &s, uint8_t value)
{
	s.write((unsigned char*) &value, 1);
}

static uint8_t readU8(uistream &s)
{
	uint8_t data;
	s.read((unsigned char*) &data, 1);
	return data;
}

static void writeU16(uostream &s, uint16_t value)
{
	uint16_t data = htobe16(value);
	s.write((unsigned char*) &data, 2);
}

static uint16_t readU16(uistream &s)
{
	uint16_t data;
	s.read((unsigned char*) &data, 2);
	return be16toh(data);
}

static int32_t readS32(uistream &s)
{
	uint32_t data;
	s.read((unsigned char*) &data, 4);
	return (int32_t) be32toh(data);
}

static std::vector<std::string> tokenize(const std::string &s)
{
	std::vector<std::string> ret;
	std::string item;
	for(char c : s) {
		if(c == ' ' || c == '\t') {
			if(!item.empty())
				ret.emplace_back(item);
			item = "";
			continue;
		}
		item += c;
	}
	if(!item.empty())
		ret.emplace_back(item);
	return ret;
}

static std::string dns_type2str(enum DNSType type)
{
	switch(type) {
		case DNS_TYPE_A:
			return "A";
		case DNS_TYPE_NS:
			return "NS";
		case DNS_TYPE_CNAME:
			return "CNAME";
		case DNS_TYPE_SOA:
			return "SOA";
		case DNS_TYPE_PTR:
			return "PTR";
		case DNS_TYPE_MX:
			return "MX";
		case DNS_TYPE_TXT:
			return "TXT";
		case DNS_TYPE_AAAA:
			return "AAAA";
		default:
			return "";
	}
}

static enum DNSType dns_str2type(const std::string &s)
{
	if(s == "A")
		return DNS_TYPE_A;
	else if(s == "NS")
		return DNS_TYPE_NS;
	else if(s == "CNAME")
		return DNS_TYPE_CNAME;
	else if(s == "PTR")
		return DNS_TYPE_PTR;
	else if(s == "AAAA")
		return DNS_TYPE_AAAA;
	else if(s == "ANY")
		return DNS_QTYPE_ANY;
	return (enum DNSType) 0;
}


DecodeException::DecodeException(const char *file, int line, const char *func)
{
	std::ostringstream oss;
	oss << "at " <<file << ":" << line << " " << func;
	text = oss.str();
}


void DNSName::encode(uostream &s) const
{
	for(auto &lbl : labels) {
		DECODE_ASSERT(lbl.size() < 64);
		writeU8(s, lbl.size());
		s.write((unsigned char*) lbl.c_str(), lbl.size());
	}
	writeU8(s, 0);
}

void DNSName::decode(uistream &s, const ustring &whole_pkt, bool can_recurse)
{
	labels.clear();
	while(true) {
		uint8_t c = readU8(s);
		if((c & 0xc0) == 0xc0) { // message compression
			// TODO: nested compression is uncommon but allowed
			DECODE_ASSERT(can_recurse);
			uint16_t offset = (c << 8) | readU8(s);
			offset &= ~0xc000;

			DECODE_ASSERT(offset < whole_pkt.size());
			uistringstream s2(whole_pkt.substr(offset, whole_pkt.size() - offset));
			return decode(s2, whole_pkt, false);
		}
		if(c == 0) // terminating zero-length label
			break;

		// ordinary label
		DECODE_ASSERT(c < 64);
		char buf[64] = { 0 };
		s.read((unsigned char*) buf, c);
		labels.emplace_back(std::string(buf));
	}
}

std::string DNSName::toString() const
{
	if(labels.empty())
		return ".";
	std::ostringstream oss;
	for(auto &lbl : labels)
		oss << lbl << ".";
	return oss.str();
}

void DNSName::parse(const std::string &s)
{
	labels.clear();
	std::string lbl;
	for(char c : s) {
		if(c == '.') {
			labels.emplace_back(lbl);
			lbl = "";
			continue;
		}
		lbl += c;
	}
	DECODE_ASSERT(lbl.empty());
	labels.shrink_to_fit();
}


void DNSQuestion::encode(uostream &s) const
{
	name.encode(s);
	writeU16(s, qtype);
	writeU16(s, qclass);
}

void DNSQuestion::decode(uistream &s, const ustring &whole_pkt)
{
	name.decode(s, whole_pkt);
	qtype = (enum DNSType) readU16(s);
	qclass = (enum DNSClass) readU16(s);
}

void DNSQuestion::parse(const std::string &s)
{
	auto items = tokenize(s);
	std::string class_, type;

	name.parse(items[0]);
	if(items.size() == 2) { // <name> <type>
		class_ = "IN";
		type = items[1];
	} else if(items.size() == 3) { // <name> <class> <type>
		class_ = items[1];
		type = items[2];
	} else {
		DECODE_ASSERT(false);
	}

	qtype = dns_str2type(type);
	DECODE_ASSERT(qtype != (enum DNSType) 0);

	if(class_ == "IN")
		qclass = DNS_CLASS_IN;
	else if(class_ == "CH")
		qclass = DNS_CLASS_CH;
	else if(class_ == "ANY")
		qclass = DNS_QCLASS_ANY;
	else
		DECODE_ASSERT(false);
}


void DNSAnswer::decode(uistream &s, const ustring &whole_pkt)
{
	name.decode(s, whole_pkt);
	type = (enum DNSType) readU16(s);
	class_ = (enum DNSClass) readU16(s);
	ttl = readS32(s);
	uint16_t rdlength = readU16(s);

	switch(type) {
		case DNS_TYPE_A:
			DECODE_ASSERT(rdlength == 4);
			s.read((unsigned char*) &rdata.addr4.s_addr, 4);
			break;
		case DNS_TYPE_AAAA:
			DECODE_ASSERT(rdlength == 16);
			s.read((unsigned char*) &rdata.addr6.s6_addr, 16);
			break;
		case DNS_TYPE_NS:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_PTR:
			rdata.name.decode(s, whole_pkt);
			break;
		default:
			// TODO
			s.seekg(rdlength, std::ios::cur);
			break;
	}
}

std::string DNSAnswer::toString() const
{
	std::ostringstream oss;
	oss << name.toString() << "\t";
	oss << (int) ttl << "\t";
	if(class_ == DNS_CLASS_IN)
		oss << "IN";
	else if(class_ == DNS_CLASS_CH)
		oss << "CH";
	oss << "\t";
	oss << dns_type2str(type) << "\t";
	switch(type) {
		case DNS_TYPE_A: {
			char dst[INET_ADDRSTRLEN];
			oss << inet_ntop(AF_INET, &rdata.addr4, dst, INET_ADDRSTRLEN);
			break;
		}
		case DNS_TYPE_AAAA: {
			char dst[INET6_ADDRSTRLEN];
			oss << inet_ntop(AF_INET6, &rdata.addr6, dst, INET6_ADDRSTRLEN);
			break;
		}
		case DNS_TYPE_NS:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_PTR:
			oss << rdata.name.toString();
			break;
		default:
			oss << "???"; // TODO
			break;
	}
	return oss.str();
}


void DNSPacket::encode(ustring *data) const
{
	uostringstream s;

	writeU16(s, txid);
	DECODE_ASSERT((flags & 0x8000) == 0); // answer bit == 0
	writeU16(s, flags);
	writeU16(s, questions.size());
	DECODE_ASSERT(answers.empty());
	writeU16(s, 0);
	writeU16(s, 0);
	writeU16(s, 0);
	for(auto &q : questions)
		q.encode(s);

	*data = s.str();
}

void DNSPacket::decode(const ustring &data)
{
	uistringstream s(data);
	s.exceptions(std::istream::eofbit);

	txid = readU16(s);
	flags = readU16(s);
	DECODE_ASSERT((flags & 0x8000) != 0); // answer bit == 1
	uint16_t qdcount = readU16(s);
	uint16_t ancount = readU16(s);
	readU16(s);
	readU16(s);
	questions.clear();
	for(int i = 0; i < qdcount; i++) {
		DNSQuestion q;
		q.decode(s, data);
		questions.emplace_back(q);
	}
	answers.clear();
	for(int i = 0; i < ancount; i++) {
		DNSAnswer a;
		a.decode(s, data);
		answers.push_back(a);
	}
}
