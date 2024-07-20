# UDP

A toy completion of the SOCKS5 protocol for UDP.

Include strictly everything in the SOCKS5 protocol for UDP, and nothing more, though the protocol is ambiguous.

The packets which is exchanged between the client and the proxy has an additional header. The code handles it successfully.

Given that in the general case, some udp client may not strictly follow the protocol, the toy code is not guaranteed to work in all cases.