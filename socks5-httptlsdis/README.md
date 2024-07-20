Get domain name from HTTP request or
HTTPS SNI field, and route the traffic.

Including a simple TLS parser to get SNI.

```
+---------+   +--------------+   +--------------+   +----------+
| User ->-+---+-> Proxy 1 ->-+---+-> Proxy 2 ->-+---+-> Server |
+---------+   +--------------+   +--------------+   +----------+
```