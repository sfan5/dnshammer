# Utilities

## `rdns1`, `rdns2`

These two utilities help with resolving the reverse DNS of IPv6's.

`rdns1` takes IPv6 addresses on stdin and outputs DNS queries readable for DNSHammer on stdout.
`rdns2` takes records as output by DNSHammer on stdin and prints the IP and hostname on stdout for lines with valid reverse PTRs.
