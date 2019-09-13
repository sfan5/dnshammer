#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>

#include "socket.hpp"

bool SocketAddress::parseIP(const std::string &s)
{
	int r;
	addr.sin6_family = AF_INET6;

	// try parsing as ipv6
	r = inet_pton(AF_INET6, s.c_str(), &addr.sin6_addr);
	if(r == 1)
		return true;

	// parse as ipv4 and convert to ipv4-mapped ipv6
	struct in_addr tmp;
	r = inet_pton(AF_INET, s.c_str(), &tmp);
	if(r != 1)
		return false;
	static const unsigned char b[12] =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; // the ::ffff: prefix
	memcpy(addr.sin6_addr.s6_addr, b, 12);
	memcpy(&addr.sin6_addr.s6_addr[12], &tmp.s_addr, 4);
	return true;
}

int SocketAddress::getPort() const
{
	return ntohs(addr.sin6_port);
}

void SocketAddress::setPort(int port)
{
	addr.sin6_port = htons(port & 0xffff);
}


Socket::Socket()
{
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(fd == -1)
		throw SocketException();
}

Socket::~Socket()
{
	if(fd != -1)
		::close(fd);
}

void Socket::sendto(const ustring &data, const struct SocketAddress &host)
{
	ssize_t r;
	r = ::sendto(fd, data.c_str(), data.size(), 0, 
		(struct sockaddr*) &host.addr, sizeof(host.addr));
	if(r == -1)
		throw SocketException();
}

void Socket::recv(size_t n, ustring *data)
{
	unsigned char buf[n];
	ssize_t r;
	r = ::recv(fd, buf, n, 0);
	if(r == -1)
		throw SocketException();
	*data = ustring(buf, r);
}

short Socket::poll(short events, int timeout)
{
	if(fd == -1)
		return POLLNVAL;
	struct pollfd pfd;
	int r;
	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;
	r = ::poll(&pfd, 1, timeout);
	if(r == -1)
		throw SocketException();
	return pfd.revents;
}

void Socket::close()
{
	::close(fd);
	fd = -1;
}
