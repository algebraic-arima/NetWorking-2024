# Demo

A demo for proxy1 with socks5-name-based routing

```
+----------+   +--------------+   +--------------+   +-----------+
|  User ->-+---+-> Proxy 1 ->-+---+-> Proxy 2 ->-+---+-> Server  |
+----------+   +--------------+   +--------------+   +-----------+
```

In proxy1, we use socks5 address
to route the traffic to **proxy2**, or 
connect **directly**, or **reject**.