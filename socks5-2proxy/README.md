# A demo for proxy1 with socks5 name-based distribution

```
+---------+   +--------------+   +--------------+   +----------+
| User ->-+---+-> Proxy 1 ->-+---+-> Proxy 2 ->-+---+-> Server |
+---------+   +--------------+   +--------------+   +----------+
```

In proxy1, we use socks5 address
for routing the traffic to proxy2, or 
connect directly, or forbidden.