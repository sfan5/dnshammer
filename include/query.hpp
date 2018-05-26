#ifndef QUERY_HPP
#define QUERY_HPP

#include <vector>
#include <ostream>

struct SocketAddress;
struct DNSQuestion;

/*
	The Transaction ID of DNS packets is composed of two numbers:
	1) Index of the resolver (16 - TXID_COUNTER_BITS) bits
	2) Number of this packet for this resolver (TXID_COUNTER_BITS) bits
	Together they are used to keep track of DNS queries sent / recevied.
	As a logical consequence, you can the maximum number of
	- resolvers is 2^(16 - TXID_COUNTER_BITS)
	- "in-flight" queries per resolver is 2^(TXID_COUNTER_BITS)
*/
#define TXID_COUNTER_BITS (3)

int query_main(std::ostream &outfile,
	bool quiet, unsigned concurrent,
	std::vector<SocketAddress> &resolvers,
	std::vector<DNSQuestion> &queries);

#endif // QUERY_HPP
