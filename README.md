# DNSHammer

Need to hit lots of nails at once? Just use a big hammer.

## How do I use this?

First, you need a list of working DNS resolvers.
Second, write a list of queries you'd like to make.

These take the format of `google.com. AAAA` or `iana.org. IN ANY`.
Note that the trailing dot is **mandatory**.

Finally:
```
$ dnshammer -r resolver_ips.txt -o answers.txt queries.txt
```

## What about `-c` / `--concurrent`?

DNSHammer will send queries to the resolvers as fast as they answer, there is no ratelimiting.
By default it will try to always have 2 queries "waiting" (sent to the server) at any given moment.

Assuming an average response time of 50ms, this translates to 40 queries per second, which should be plenty.

If you see too many lost queries (the percent value in the status message), you may want to use `-c 1`.
Though, this doesn't matter as much since DNSHammer automatically throttles (see below).

## What if some resolvers stop working / have rate limits?

Queries which do no receive an answer (time out) are retried with a different resolver.
The timeout for each DNS query is 3 seconds.

If a resolver drops a (single) query, DNSHammer will continue querying it, just with one concurrent query less than before.
This means non-functional resolvers are automatically weeded out without impacting the quality of the results.

## Which DNS types are supported?

Queries can use everything you usually see in DNS (except for DNSSEC stuff).

For answers I only bothered to implement `A`, `AAAA`, `NS`, `CNAME` and `PTR`. Pull requests are welcome.

## Why does this use so much memory?

DNSHammer keeps all queries in memory in a parsed state, this is not too memory-efficient,
for example 500k IPv6 rDNS queries (`[...].ip6.arpa. IN PTR`) take roughly 500 MB.

You'll just need to live with it.

## How many resolvers do I need?

I wrote this tool to mass-resolve reverse DNS of IPv6 hosts, and from experience
2000 resolvers are enough to complete millions of DNS queries in reasonable time.

So, most likely *few*.
