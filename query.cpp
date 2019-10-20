#include <stdio.h> // snprintf()
#include <poll.h> // POLL* constants
#include <time.h> // clock_gettime
#include <iostream>
#include <fstream>
#include <set>
#include <vector>
#include <deque>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <unordered_map>

#include "query.hpp"
#include "common.hpp"
#include "socket.hpp"
#include "dns.hpp"

using MutexAutoLock = std::unique_lock<std::mutex>;
static inline time_t clock_monotonic();

struct Resolver
{
	SocketAddress addr;
	unsigned capacity;

	Resolver(SocketAddress &addr, unsigned capacity) :
		addr(addr), capacity(capacity) {}
	inline bool acquireCapacity() {
		if (capacity == 0)
			return false;
		capacity--;
		return true;
	}
	inline void restoreCapacity() { capacity++; }
};

struct PendingQuery
{
	size_t query_id;
	size_t resolver_id;
	time_t time_sent;

	PendingQuery(size_t query_id, size_t resolver_id) :
		query_id(query_id), resolver_id(resolver_id) {
		time_sent = clock_monotonic();
	}
};

static void print_stats(uint32_t n_sent, uint32_t n_recv, uint32_t n_succ);
static void recv_thread(
	std::ostream &outfile,
	uint32_t *n_recv, uint32_t *n_succ);
static void timeout_thread(bool *should_exit);
static void send_thread(
	uint32_t *n_sent, const std::vector<DNSQuestion> queries,
	bool *has_pending, bool *should_exit);
static void build_packet(const DNSQuestion &question, DNSPacket *pkt, uint16_t txid);
static bool check_answer(const DNSPacket &pkt);

static struct {
	Socket *sock;

	std::mutex mtx;
	std::vector<Resolver> resolvers;
	std::deque<size_t> send_queue;
	std::unordered_map<uint16_t, PendingQuery> pending;
} g;

int query_main(std::ostream &outfile,
	bool quiet, unsigned concurrent,
	std::vector<SocketAddress> &resolvers,
	std::vector<DNSQuestion> &queries)
{
	g.resolvers.reserve(resolvers.size());
	for(auto &addr : resolvers)
		g.resolvers.emplace_back(Resolver(addr, concurrent));

	for(size_t i = 0; i < queries.size(); i++)
		g.send_queue.emplace_back(i);

	g.sock = new Socket();

	std::cerr << "Running with " << resolvers.size() << " resolvers and " << queries.size() << " queries." << std::endl;
	std::cerr << std::endl;

	uint32_t n_recv = 0, n_succ = 0;
	uint32_t n_sent = 0;
	bool should_exit = false, has_pending = true;
	std::thread t_recv(recv_thread, std::ref(outfile), &n_recv, &n_succ);
	std::thread t_timeout(timeout_thread, &should_exit);
	std::thread t_send(send_thread, &n_sent, queries, &has_pending, &should_exit);

	{
		uint32_t prev_n_sent = 0, hang_count = 0;
		do {
			if(!quiet)
				print_stats(n_sent, n_recv, n_succ);

			if(n_sent == prev_n_sent) {
				if(++hang_count == TIMEOUT_SEC + 1) {
					if(has_pending) {
						std::cerr << std::endl << "Error: No resolvers are responding anymore, exiting." << std::endl;
						outfile.flush();
						_Exit(1); // hard exit, since we can't kill t_send
					}
					should_exit = true;
					break;
				}
			} else {
				hang_count = 0;
			}

			prev_n_sent = n_sent;
			std::this_thread::sleep_for(std::chrono::seconds(1));
		} while(1);
	}

	t_send.join();
	t_timeout.join();
	std::cerr << "\nDone!" << std::endl;

	// close the socket and wait for t_recv to exit
	g.sock->close();
	t_recv.join();

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
		{
			short ev = g.sock->poll(POLLIN, 1000);
			if(ev == 0)
				continue;
			else if(ev & POLLNVAL)
				break; // we're done here
		}
		g.sock->recv(4096, &data);

		try {
			pkt.decode(data);
		} catch(const DecodeException &e) {
			std::cerr << "A packet failed to decode " << e.what() << std::endl;
			continue;
		} catch(const std::ios_base::failure& e) {
			std::cerr << "A packet failed to decode (truncated)" << std::endl;
			continue;
		}

		{
			MutexAutoLock alock(g.mtx);
			auto it = g.pending.find(pkt.txid);
			if(it == g.pending.end()) {
				std::cerr << "Unexpected answer txid (late answer?)" << std::endl;
				continue;
			}

			/* success handling */
			size_t resolver_id = it->second.resolver_id;
			g.resolvers[resolver_id].restoreCapacity();

			g.pending.erase(it);
		}

		bool has_records = check_answer(pkt);
		if(has_records) {
			for(auto &a : pkt.answers)
				outfile << a.toString() << "\n";
		}

		*n_recv += 1;
		*n_succ += has_records ? 1 : 0;
	}
}

static void send_thread(uint32_t *n_sent, const std::vector<DNSQuestion> queries, bool *has_pending, bool *should_exit)
{
	size_t resolver_id = 0;
	uint16_t txid = 0;
	DNSPacket pkt;
	ustring data;

	do {
		size_t query_id;
		bool any = false;
		{
			MutexAutoLock alock(g.mtx);
			*has_pending = any = !g.send_queue.empty();
			if(any) {
				query_id = g.send_queue.front();
				g.send_queue.pop_front();
			}
		}

		if(!any) {
			if(*should_exit)
				break;
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			continue;
		}

		// find resolver with capacity
retry_resolver:
		size_t start = resolver_id;
		any = false;
		{
			MutexAutoLock alock(g.mtx);
			do {
				if(g.resolvers[resolver_id].acquireCapacity()) {
					any = true;
					break;
				}
				resolver_id = (resolver_id + 1) % g.resolvers.size();
			} while(resolver_id != start);
		}
		if(!any) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			goto retry_resolver;
		}

		// find unused txid
retry_txid:
		start = txid;
		any = false;
		{
			MutexAutoLock alock(g.mtx);
			do {
				if(g.pending.find(txid) == g.pending.cend()) {
					any = true;
					break;
				}
				txid++;
			} while(txid != start);
		}
		if(!any) {
			std::cerr << "No free query txid (should usually not happen)" << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			goto retry_txid;
		}

		// actually send packet
		build_packet(queries[query_id], &pkt, txid);
		pkt.encode(&data);
		g.sock->sendto(data, g.resolvers[resolver_id].addr);

		{
			MutexAutoLock alock(g.mtx);
			g.pending.emplace(txid, PendingQuery(query_id, resolver_id));
		}

		*n_sent += 1;
	} while(1);
}

static void timeout_thread(bool *should_exit)
{
	while(1) {
again:
		time_t cutoff = clock_monotonic() - TIMEOUT_SEC;

		g.mtx.lock();
		for(auto it = g.pending.begin(); it != g.pending.end(); it++) {
			if(it->second.time_sent <= cutoff) {
				/* expire handling */
				g.send_queue.emplace_back(it->second.query_id);

				g.pending.erase(it);
				g.mtx.unlock();
				goto again; // iterate again immediately
			}
		}
		g.mtx.unlock();

		if(*should_exit)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(TIMEOUT_SEC * 1000 / 2));
	}
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

static inline time_t clock_monotonic()
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec;
}
