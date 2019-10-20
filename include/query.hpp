#ifndef QUERY_HPP
#define QUERY_HPP

#include <vector>
#include <ostream>

struct SocketAddress;
struct DNSQuestion;

#define TIMEOUT_SEC 6

int query_main(std::ostream &outfile,
	bool quiet, unsigned concurrent,
	std::vector<SocketAddress> &resolvers,
	std::vector<DNSQuestion> &queries);

#endif // QUERY_HPP
