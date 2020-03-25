#include <poll.h> // POLL* constants
#include <time.h> // clock_gettime
#include <iostream>
#include <vector>
#include <deque>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <functional>

#include "backend.hpp"
#include "common.hpp"
#include "socket.hpp"
#include "dns.hpp"

using MutexAutoLock = std::unique_lock<std::mutex>;
static inline time_t clock_monotonic();
static inline ustring encode_u16(uint16_t v);

struct PendingQuery
{
	QueryID id;
	size_t resolver_id;
	time_t time_sent;

	PendingQuery(QueryID id, size_t resolver_id) :
		id(id), resolver_id(resolver_id) {
		time_sent = clock_monotonic();
	}
};

QueryBackend::QueryBackend(const std::vector<SocketAddress> &resolvers,
	unsigned concurrent, time_t timeout, bool timeout_keep_cap)
	: timeout(timeout), timeout_keep_cap(timeout_keep_cap)
{
	this->resolvers.reserve(resolvers.size());
	for(auto &addr : resolvers)
		this->resolvers.emplace_back(Resolver(addr, concurrent));
}

void QueryBackend::setCallbacks(
	std::function<DNSQuestion(QueryID)> callback_question,
	std::function<void(const DNSPacket&, QueryID)> callback_answer,
	std::function<void(QueryID)> callback_timeout)
{
	this->callback_question = callback_question;
	this->callback_answer = callback_answer;
	this->callback_timeout = callback_timeout;
}

void QueryBackend::queue(QueryID id)
{
	MutexAutoLock alock(mtx);

	send_queue.emplace_back(id);
}

void QueryBackend::start()
{
	n_sent = n_recv = 0;
	n_queue = send_queue.size();
	should_exit = false;

	t_recv = new std::thread(&QueryBackend::recv_thread, this);
	t_timeout = new std::thread(&QueryBackend::timeout_thread, this);
	t_send = new std::thread(&QueryBackend::send_thread, this);
}

void QueryBackend::getStats(uint32_t *n_sent, uint32_t *n_queue, uint32_t *n_recv, bool reset)
{
	if(n_sent)
		*n_sent = reset ? this->n_sent.exchange(0) : this->n_sent.load();
	if(n_queue)
		*n_queue = this->n_queue;
	if(n_recv)
		*n_recv = reset ? this->n_recv.exchange(0) : this->n_recv.load();
}

void QueryBackend::stopJoin()
{
	should_exit = true;
	t_send->join();
	t_timeout->join();

	// close the socket and wait for t_recv to exit
	sock.close();
	t_recv->join();

	delete t_send;
	delete t_timeout;
	delete t_recv;
	t_send = t_timeout = t_recv = nullptr;
}

void QueryBackend::recv_thread()
{
	ustring data;
	DNSPacket pkt;
	SocketAddress src_addr;

	while(1) {
		{
			short ev = sock.poll(POLLIN, 1000);
			if(ev == 0)
				continue;
			else if(ev & POLLNVAL)
				break; // we're done here
		}
		sock.recvfrom(4096, &data, src_addr);

		try {
			pkt.decode(data);
		} catch(const DecodeException &e) {
			std::cerr << "A packet failed to decode " << e.what() << std::endl;
			continue;
		} catch(const std::ios_base::failure &e) {
			std::cerr << "A packet failed to decode (truncated)" << std::endl;
			continue;
		}

		PendingQuery *p;
		const ustring key = src_addr.getIPBytes() + encode_u16(pkt.txid);
		{
			MutexAutoLock alock(mtx);
			auto it = pending.find(key);
			if(it == pending.end()) {
				std::cerr << "Unexpected answer packet (late answer?)" << std::endl;
				continue;
			}
			p = it->second;
			pending.erase(it);

			resolvers[p->resolver_id].restoreCapacity();
		}

		callback_answer(pkt, p->id);
		delete p;

		n_recv++;
	}
}

void QueryBackend::send_thread()
{
	size_t resolver_id = 0;
	DNSPacket pkt;
	ustring data;

	pkt.flags = 0x0100; // QUERY opcode, RD=1

	do {
		QueryID id = 0; // shut up gcc
		bool any;
		{
			MutexAutoLock alock(mtx);
			any = !send_queue.empty();
			if(any) {
				id = send_queue.front();
				send_queue.pop_front();
				n_queue = send_queue.size();
			} else {
				n_queue = 0;
			}
		}

		if(should_exit)
			break;
		if(!any) {
			std::this_thread::sleep_for(std::chrono::milliseconds(25));
			continue;
		}

		// find resolver with capacity
retry_resolver:
		size_t start = resolver_id;
		any = false;
		{
			MutexAutoLock alock(mtx);
			do {
				if(resolvers[resolver_id].acquireCapacity()) {
					any = true;
					break;
				}
				resolver_id = (resolver_id + 1) % resolvers.size();
			} while(resolver_id != start);
		}
		if(!any) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			goto retry_resolver;
		}
		Resolver &res = resolvers[resolver_id];

		// grab the next txid
		// assumption: timeout * capacity << 0xffff so that txids never overlap
		uint16_t txid = res.nextTxid();

		// build and send the packet
		pkt.txid = txid;
		pkt.questions.clear();
		pkt.questions.emplace_back(callback_question(id));
		pkt.encode(&data);
		sock.sendto(data, res.addr);

		const ustring key = res.addr.getIPBytes() + encode_u16(pkt.txid);
		{
			MutexAutoLock alock(mtx);
			pending.emplace(key, new PendingQuery(id, resolver_id));
		}

		n_sent++;
	} while(1);
}

void QueryBackend::timeout_thread()
{
	while(1) {
again:
		time_t cutoff = clock_monotonic() - timeout;

		mtx.lock();
		for(auto it = pending.begin(); it != pending.end(); it++) {
			if(it->second->time_sent <= cutoff) {
				PendingQuery *p = it->second;
				pending.erase(it);
				if(timeout_keep_cap)
					resolvers[p->resolver_id].restoreCapacity();
				mtx.unlock();

				callback_timeout(p->id);
				delete p;

				goto again; // iterate again immediately
			}
		}
		mtx.unlock();

		if(should_exit)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(timeout * 1000 / 2));
	}
}

static inline time_t clock_monotonic()
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec;
}

static inline ustring encode_u16(uint16_t v)
{
	return ustring(reinterpret_cast<unsigned char*>(&v), 2);
}
