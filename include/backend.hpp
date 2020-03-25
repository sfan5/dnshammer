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
struct QueuedQuery;
struct PendingQuery;

class QueryBackend {
public:
	QueryBackend(const std::vector<SocketAddress> &resolvers,
		unsigned concurrent, time_t timeout);

	void setCallbacks(std::function<void(const DNSPacket&, size_t)> callback,
		std::function<void(size_t)> callback_timeout);

	void queue(const DNSQuestion &question, size_t id);

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

	std::atomic<uint32_t> n_sent, n_recv;
	uint32_t n_queue;
	bool should_exit;
	std::thread *t_recv = nullptr, *t_send = nullptr, *t_timeout = nullptr;

	std::function<void(const DNSPacket&, size_t)> callback = nullptr;
	std::function<void(size_t)> callback_timeout = nullptr;

	std::mutex mtx;
	std::vector<Resolver> resolvers;
	std::deque<QueuedQuery*> send_queue;
	std::unordered_map<ustring, PendingQuery*> pending;
};

#endif // BACKEND_HPP
