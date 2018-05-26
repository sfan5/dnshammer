#ifndef SOCKET_HPP
#define SOCKET_HPP

#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <exception>

#include "common.hpp"

class SocketException : public std::exception {
public:
	SocketException() : err(errno) {};
	const char* what() const noexcept { return strerror(err); };

private:
	int err;
};

struct SocketAddress {
	struct sockaddr_in6 addr = { 0 };

	bool parseIP(const std::string &s);
	int getPort() const;
	void setPort(int port);
};

// represents an IPv6 UDP socket
class Socket {
public:
	Socket();
	~Socket();

	void sendto(const ustring &data, const SocketAddress &host);
	void recv(size_t n, ustring *data);
	void close();

private:
	int fd;
};

#endif // SOCKET_HPP
