#include <getopt.h>
#include <iostream>
#include <fstream>
#include <set>

#include "common.hpp"
#include "socket.hpp"
#include "dns.hpp"
#include "query.hpp"

static void usage();
static bool parse_resolver_list(std::istream &s, std::vector<SocketAddress> &res);
static bool parse_query_list(std::istream &s, std::vector<DNSQuestion> &res);
static void trim(std::string &s, const std::set<char> &trimchars);

int main(int argc, char *argv[])
{
	const struct option long_options[] = {
		{"concurrent", required_argument, 0, 'c'},
		{"help", no_argument, 0, 'h'},
		{"output-file", required_argument, 0, 'o'},
		{"quiet", no_argument, 0, 'q'},
		{"resolvers", required_argument, 0, 'r'},
		{0,0,0,0},
	};

	std::ostream *outfile = &std::cout;
	std::vector<SocketAddress> resolvers;
	bool quiet = false;
	unsigned concurrent = 2;
	std::vector<DNSQuestion> queries;

	while(1) {
		int c = getopt_long(argc, argv, "c:ho:qr:", long_options, NULL);
		if(c == -1)
			break;
		switch(c) {
			case 'c': {
				std::istringstream iss(optarg);
				concurrent = -1;
				iss >> concurrent;

				if(concurrent < 1) {
					std::cerr << "Invalid value for --concurrent." << std::endl;
					return 1;
				}
				break;
			}
			case 'h':
				usage();
				return 1;
			case 'o':
				outfile = new std::ofstream(optarg);
				if(!outfile->good()) {
					std::cerr << "Failed to open output file." << std::endl;
					return 1;
				}
				break;
			case 'q':
				quiet = true;
				break;
			case 'r': {
				std::ifstream f(optarg);
				if(!f.good()) {
					std::cerr << "Failed to open file." << std::endl;
					return 1;
				}
				if(!parse_resolver_list(f, resolvers))
					return 1;
				break;
			}
			default:
				break;
		}
	}

	if(argc - optind != 1) {
		usage();
		return 1;
	}
	{
		std::ifstream f(argv[optind]);
		if(!f.good()) {
			std::cerr << "Failed to open file." << std::endl;
			return 1;
		}
		if(!parse_query_list(f, queries))
			return 1;
	}

	if(queries.empty()) {
		std::cerr << "At least one query is required." << std::endl;
		return 1;
	}
	if(resolvers.empty()) {
		std::cerr << "At least one resolver is required." << std::endl;
		return 1;
	}

	resolvers.shrink_to_fit();
	queries.shrink_to_fit();

	int ret = query_main(*outfile, quiet, concurrent, resolvers, queries);
	outfile->flush();

	return ret;
}

static void usage(void)
{
	std::cout
		<< "DNSHammer completes lots of DNS queries asynchronously" << std::endl
		<< "Usage: dnshammer [options] <file with queries>" << std::endl
		<< "Options:" << std::endl
		<< "  -h|--help               This text" << std::endl
		<< "  -r|--resolvers <file>   List of resolvers to query" << std::endl
		<< "  -o|--output-file <file> Output file (defaults to standard output)" << std::endl
		<< "  -c|--concurrent <n>     Number of concurrent requests per resolver (defaults to 2)" << std::endl
		<< "  -q|--quiet              Disable periodic status message" << std::endl
	;
}

static const std::set<char> whitespace{' ', '\t', '\r', '\n'};

static inline bool is_ip_duplicate(const SocketAddress &search, const std::vector<SocketAddress> &in)
{
	for(const auto &addr : in) {
		if(!memcmp(&addr.addr.sin6_addr.s6_addr, &search.addr.sin6_addr.s6_addr, 16))
			return true;
	}
	return false;
}

static bool parse_resolver_list(std::istream &s, std::vector<SocketAddress> &res)
{
	while(1) {
		char buf[1024] = {0};
		bool ok = !!s.getline(buf, sizeof(buf) - 1);
		if(!ok)
			break;

		std::string s(buf);
		trim(s, whitespace);

		if(s.empty() || s[0] == '#')
			continue; // skip comments and empty lines

		SocketAddress addr;
		if(!addr.parseIP(s)) {
			std::cerr << "\"" << s << "\" is not a valid IP." << std::endl;
			return false;
		}
		addr.setPort(53); // TODO: make this configurable?

		if(is_ip_duplicate(addr, res)) {
			std::cerr << "Resolver addresses maybe not be duplicate" << std::endl;
			return false;
		}

		res.emplace_back(addr);
	}
	return true;
}

static bool parse_query_list(std::istream &s, std::vector<struct DNSQuestion> &res)
{
	while(1) {
		char buf[1024] = {0};
		bool ok = !!s.getline(buf, sizeof(buf) - 1);
		if(!ok)
			break;

		std::string s(buf);
		trim(s, whitespace);

		if(s.empty() || s[0] == '#')
			continue; // skip comments and empty lines

		struct DNSQuestion q;
		try {
			q.parse(s);
		} catch(DecodeException &e) {
			std::cerr << "\"" << s << "\" is not a valid DNS question." << std::endl;
			return false;
		}

		res.emplace_back(q);
	}
	return true;
}

static void trim(std::string &s, const std::set<char> &trimchars)
{
	// front
	size_t i = 0;
	while(i < s.size() && trimchars.find(s[i]) != trimchars.cend())
		i++;
	if(i > 0)
		s = s.substr(i, s.size() - i);

	// back
	i = s.size() - 1;
	while(i >= 0 && trimchars.find(s[i]) != trimchars.cend())
		i--;
	s.resize(i + 1);
}
