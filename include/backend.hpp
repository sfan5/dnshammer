#ifndef BACKEND_HPP
#define BACKEND_HPP

#include <functional>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <stddef.h>

#include "socket.hpp"

using QueryID = intptr_t;

struct SocketAddress;
struct DNSQuestion;
struct DNSPacket;

struct Resolver
{
	SocketAddress addr;
	unsigned capacity;
	uint16_t txid;

	Resolver(const SocketAddress &addr, unsigned capacity) :
		addr(addr), capacity(capacity), txid(0) {}
	inline bool acquireCapacity() {
		if (capacity == 0)
			return false;
		capacity--;
		return true;
	}
	inline void restoreCapacity() { capacity++; }
	inline uint16_t nextTxid() { return txid++; }
};
struct PendingQuery;

class QueryBackend {
public:
	QueryBackend(const std::vector<SocketAddress> &resolvers,
		unsigned concurrent, time_t timeout, bool timeout_keep_cap=false);

	void setCallbacks(
		std::function<DNSQuestion(QueryID)> callback_question,
		std::function<void(const DNSPacket&, QueryID)> callback_answer,
		std::function<void(QueryID)> callback_timeout);

	void queue(QueryID id);

	void start();
	void getStats(uint32_t *n_sent, uint32_t *n_queue, uint32_t *n_recv,
		bool reset=false);
	void stopJoin();

private:
	void recv_thread();
	void send_thread();
	void timeout_thread();

	Socket sock;
	time_t timeout;
	bool timeout_keep_cap;

	std::atomic<uint32_t> n_sent, n_recv;
	uint32_t n_queue;
	bool should_exit;
	std::thread *t_recv = nullptr, *t_send = nullptr, *t_timeout = nullptr;

	std::function<DNSQuestion(QueryID)> callback_question = nullptr;
	std::function<void(const DNSPacket&, QueryID)> callback_answer = nullptr;
	std::function<void(QueryID)> callback_timeout = nullptr;

	std::mutex mtx;
	std::vector<Resolver> resolvers;
	std::deque<QueryID> send_queue;
	std::unordered_map<ustring, PendingQuery*> pending;
};

#endif // BACKEND_HPP
