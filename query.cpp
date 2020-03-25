#include <stdio.h> // snprintf()
#include <iostream>
#include <fstream>
#include <deque>
#include <thread>
#include <mutex>

#include "query.hpp"
#include "common.hpp"
#include "backend.hpp"
#include "dns.hpp"

static void print_stats(uint32_t n_sent, uint32_t n_recv, uint32_t n_succ);
static bool check_answer(const DNSPacket &pkt);

int query_main(std::ostream &outfile,
	bool quiet, unsigned concurrent,
	std::vector<SocketAddress> &resolvers,
	std::vector<DNSQuestion> &queries)
{
	QueryBackend backend(resolvers, concurrent, TIMEOUT_SEC);

	uint32_t n_succ = 0;
	auto cb_query = [&] (QueryID id) -> DNSQuestion {
		return queries[id];
	};
	auto cb_answer = [&] (const DNSPacket &pkt, QueryID id) {
		bool has_records = check_answer(pkt);
		if(has_records) {
			for(auto &a : pkt.answers)
				outfile << a.toString() << "\n";
		}
		n_succ += has_records ? 1 : 0;
	};
	auto cb_timeout = [&] (QueryID id) {
		// retry query
		backend.queue(id);
	};
	backend.setCallbacks(cb_query, cb_answer, cb_timeout);

	for(size_t i = 0; i < queries.size(); i++)
		backend.queue(i);

	std::cerr << "Running with " << resolvers.size() << " resolvers and " << queries.size() << " queries." << std::endl;
	std::cerr << std::endl;

	backend.start();

	{
		uint32_t n_sent, n_queue, n_recv;
		uint32_t prev_n_sent = 0, hang_count = 0;
		do {
			backend.getStats(&n_sent, &n_queue, &n_recv);
			if(!quiet)
				print_stats(n_sent, n_recv, n_succ);

			if(n_sent == prev_n_sent) {
				if(++hang_count == TIMEOUT_SEC + 1) {
					if(n_queue > 0) {
						std::cerr << "\nError: No resolvers are responding anymore, exiting." << std::endl;
						outfile.flush();
						_Exit(1); // hard exit
					}
					break;
				}
			} else {
				hang_count = 0;
			}

			prev_n_sent = n_sent;
			std::this_thread::sleep_for(std::chrono::seconds(1));
		} while(1);
	}

	backend.stopJoin();
	std::cerr << "\nDone!" << std::endl;

	return 0;
}

static void print_stats(uint32_t n_sent, uint32_t n_recv, uint32_t n_succ)
{
	char buf[512];
	float percent = n_sent == 0 ? 0.f : (n_recv / (float) n_sent);
	percent *= 100.f;
	snprintf(buf, sizeof(buf),
		"sent %9d queries; got %9d answers (%02d%%), %9d successful\r",
		n_sent, n_recv, (int) percent, n_succ);
	std::cerr << buf;
	std::cerr.flush();
}

static bool check_answer(const DNSPacket &pkt)
{
	uint16_t rcode = pkt.flags & 0xf;
	if(rcode != 0)
		return false;
	return !pkt.answers.empty();
}
