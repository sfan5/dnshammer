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
Alternatively, if you need it to go even faster you can up the value of `-c`,
but be prepared for a higher amount of lost queries.

## What if some resolvers stop working / have rate limits?

Per the answer above, DNSHammer sends the next query as soon as a previous query is answered.
This also means that if a resolver does not respond to a query, DNSHammer will not send a new query.
Because the design is kept simple, DNSHammer doesn't know *which* queries failed,
but it will tell you how many were lost when it's finished.

The same applies to ratelimits, if a resolver drops a (single) query
DNSHammer will continue querying it, just with one "concurrent query" less than before.

## Which DNS types are supported?

Queries can use everything you usually see in DNS (except for DNSSEC stuff).
For answers I only bothered to implement `A`, `AAAA`, `NS`, `CNAME` and `PTR`.

## Why does this use so much memory?

DNSHammer keeps all queries in memory in a parsed state, this is not too memory-efficient.
For example 500k IPv6 rDNS queries (`[...].ip6.arpa. IN PTR`) take roughly 500 MB.

You'll just need to live with it.

## How many resolvers do I need?

I wrote this tool to mass-resolve reverse DNS of IPv6 hosts, and from experience
2000 resolvers are enough to complete millions of DNS queries in reasonable time.

So, most likely *few*.
