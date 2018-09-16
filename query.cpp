#include <stdio.h> // snprintf()
#include <iostream>
#include <fstream>
#include <set>
#include <vector>
#include <type_traits> // static_assert()
#include <thread>
#include <atomic>

#include "query.hpp"
#include "common.hpp"
#include "socket.hpp"
#include "dns.hpp"

#define BITMAP_T uint32_t

#define TXID(resolver_id, req_id) ( (uint16_t) ((resolver_id) << TXID_COUNTER_BITS) | (req_id) )
#define RESOLVER_ID(txid) (uint16_t) ( (txid) >> TXID_COUNTER_BITS )
#define REQ_ID(txid) (uint8_t) ( (txid) & ((1 << TXID_COUNTER_BITS) - 1) )

struct Entry
{
	SocketAddress addr; // address of the resolver
	/*
		A bitmap
		0 = we got an answer with this req_id / nothing was ever sent
		1 = packet with this req_id was sent
		the index into the bitmap is the req_id
	*/
	std::atomic<BITMAP_T> sent;

	Entry(const SocketAddress &addr);
	inline void setSent(uint8_t req_id) { sent |= (1 << req_id); }
	inline void setReceived(uint8_t req_id) { sent &= ~(1 << req_id); }
	inline bool needSend(uint8_t max) const { return sent != (BITMAP_T) ( (1 << max) - 1 ); }
	uint8_t freeId() const;
	uint8_t countBits() const;

	static_assert(sizeof(BITMAP_T) * 8 >= (1 << TXID_COUNTER_BITS), "Bitmap type is not wide enough");
};

static void print_stats(uint32_t n_sent, uint32_t n_recv, uint32_t n_succ);
static void recv_thread(
	std::ostream &outfile,
	uint32_t *n_recv, uint32_t *n_succ);
static void send_thread(
	const std::vector<DNSQuestion> *queries, unsigned concurrent,
	uint32_t *n_sent);
static void build_packet(const DNSQuestion &question, DNSPacket *pkt, uint16_t txid);
static bool check_answer(const DNSPacket &pkt);

// global variables becaue std::thread() just throws pages of template errors
static struct {
	std::vector<Entry*> entries;
	Socket *sock;
} g;

int query_main(std::ostream &outfile,
	bool quiet, unsigned concurrent,
	std::vector<SocketAddress> &resolvers,
	std::vector<DNSQuestion> &queries)
{
	std::vector<Entry*> &entries = g.entries;
	entries.reserve(resolvers.size());
	for(auto &addr : resolvers)
		entries.emplace_back(new Entry(addr));

	g.sock = new Socket();

	std::cerr << "Running with " << entries.size() << " resolvers and " << queries.size() << " queries." << std::endl;
	std::cerr << std::endl;

	uint32_t n_recv = 0, n_succ = 0;
	uint32_t n_sent = 0;
	std::thread t_recv(recv_thread, std::ref(outfile), &n_recv, &n_succ);
	std::thread t_send(send_thread, &queries, concurrent, &n_sent);

	if(!quiet) {
		do {
			print_stats(n_sent, n_recv, n_succ);
			std::this_thread::sleep_for(std::chrono::seconds(1));
		} while(n_sent < queries.size());
	}
	t_send.join();

	// wait for the last queries to be answered
	std::this_thread::sleep_for(std::chrono::seconds(6));

	// close the socket to raise a SocketException inside recv_thread
	g.sock->close();
	t_recv.join();

	// print final stats
	print_stats(n_sent, n_recv, n_succ);
	std::cerr << std::endl << std::endl;
	std::cerr << "Done!" << std::endl;
	
	int lost = 0;
	for(auto &e : entries)
		lost += e->countBits();
	if(lost > 0)
		std::cerr << "Warning: " << lost << " queries were lost (unanswered)." << std::endl;;

	for(auto &e : entries)
		delete e;
	delete g.sock;
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

static void recv_thread(std::ostream &outfile, uint32_t *n_recv, uint32_t *n_succ)
{
	ustring data;
	DNSPacket pkt;

	while(1) {
		try {
			g.sock->recv(4096, &data);
		} catch(const SocketException &e) {
			break;
		}

		try {
			pkt.decode(data);
		} catch(const DecodeException &e) {
			std::cerr << "A packet failed to decode " << e.what() << std::endl;
			continue;
		} catch(const std::ios_base::failure& e) {
			std::cerr << "A packet failed to decode (truncated)" << std::endl;
			continue;
		}

		bool has_records = check_answer(pkt);
		if(has_records) {
			for(auto &a : pkt.answers)
				outfile << a.toString() << "\n";
		}

		uint16_t resolver_id = RESOLVER_ID(pkt.txid);
		uint8_t req_id = REQ_ID(pkt.txid);
		g.entries[resolver_id]->setReceived(req_id);

		*n_recv += 1;
		*n_succ += has_records ? 1 : 0;
	}
}

static void send_thread(const std::vector<DNSQuestion> *queries, unsigned concurrent, uint32_t *n_sent)
{
	auto qit = queries->cbegin();
	DNSPacket pkt;
	ustring data;

	do {
		bool any = false;
		for(auto it = g.entries.begin(); it != g.entries.end(); it++) {
			Entry *e = *it;
			if(!e->needSend(concurrent))
				continue;

			uint16_t resolver_id = it - g.entries.begin();
			uint8_t req_id = e->freeId();

			build_packet(*qit, &pkt, TXID(resolver_id, req_id));
			qit++;

			pkt.encode(&data);
			g.sock->sendto(data, e->addr);
			e->setSent(req_id);

			any = true;
			*n_sent += 1;

			if(qit == queries->cend())
				break;
		}

		// prevent high cpu usage
		if(!any)
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
	} while(qit != queries->cend());
}

Entry::Entry(const SocketAddress &addr)
{
	this->addr = addr;
	sent = 0;
}

uint8_t Entry::freeId() const
{
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
	static_assert(sizeof(long long) >= sizeof(BITMAP_T), "Bitmap type is too wide for ffs"); 
	return __builtin_ffsll(~sent) - 1;
#else
	for(uint8_t id = 0; ; id++) {
		if((sent & (1 << id)) == 0)
			return id;
	}
	/* never reached */
#endif
}

uint8_t Entry::countBits() const
{
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
	static_assert(sizeof(unsigned long long) >= sizeof(BITMAP_T), "Bitmap type is too wide for popcount"); 
	return __builtin_popcountll(sent);
#else
	uint8_t n;
	BITMAP_T v = sent;
	for(n = 0; v; n++)
		v &= v - 1;
	return n;
#endif
}

static void build_packet(const DNSQuestion &question, DNSPacket *pkt, uint16_t txid)
{
	pkt->txid = txid;
	pkt->flags = 0x0100; // QUERY opcode, RD=1
	pkt->questions.clear();
	pkt->questions.emplace_back(question);
}

static bool check_answer(const DNSPacket &pkt)
{
	uint16_t rcode = pkt.flags & 0xf;
	if(rcode != 0)
		return false;
	return !pkt.answers.empty();
}
