#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#define SWAP(x,y) do {     \
	typeof(x) _x = x;      \
	typeof(y) _y = y;      \
	x = _y;                \
	y = _x;                \
 } while(0)

int main()
{
	// 2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.7.0.0.0.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa.	85161	IN	PTR	panda.he.net.
	// 2001:0470:0000:0071:0000:0000:0000:0002	panda.he.net.

	char buf[512];
	while(1) {
		if(!fgets(buf, sizeof(buf), stdin))
			break;

		char *tmp = strchr(buf, '\t');
		if(!tmp)
			continue;
		if(tmp != buf + 73)
			continue;

		for(int i = 1; i < 32; i++)
			buf[i + (i >> 2)] = buf[i << 1];
		for(int i = 0; i < 19; i++)
			SWAP(buf[i], buf[38 - i]);
		for(int i = 4; i < 32; i += 4)
			buf[i + (i >> 2) - 1] = ':';

		tmp = strrchr(buf, '\t');
		if(strncmp(tmp - 3, "PTR", 3))
			continue;

		int namelen = strlen(tmp);
		namelen--;
		tmp[namelen-1] = '\n';

		struct iovec iov[2] = { { buf, 39}, {tmp, namelen} };
		writev(STDOUT_FILENO, iov, 2);
	}
	return 0;
}
