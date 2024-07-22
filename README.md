# PPCA 2024 Networking

Notice: the whole project is divided into 
several parts, each part is a separate project
and can be run independently.

## 项目要求

- [简单代理服务器](base.md) [socks5-server](socks5-server)
- [代理客户端](client.md) (下列子任务都基于代理客户端的实现)
  - [分流规则](rules.md)
    - [按 socks 地址分流](rules-ip.md) [socks5-socksdis](socks5-socksdis)
    - [HTTP 分流](rules-http.md)+[TLS 分流](rules-tls.md)  [socks5-httptlsdis](socks5-httptlsdis)
    - [按程序分流](rules-program.md) [socks5-progdis](socks5-progdis)
  - [多级代理](chain.md)
- [透明代理](tun.md) [socks5-tproxy](socks5-tproxy)
- [TLS 劫持](tls.md)+[HTTP 捕获/修改/重放](replay.md) [socks5-tlsinterf](socks5-tleinterf)

- [UDP 代理](udp.md) [socks5-udp](socks5-udp)
- [反向代理](reverse.md)

## 参考资料

**参考书**:

- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [High Performance Browser Networking](https://hpbn.co/)
  - 书中内容远超出此次项目的要求, 只看 Networking 101 及 HTTP 中的一部分即可
  - [中文版 pdf](https://jbox.sjtu.edu.cn/l/O1voXQ)
- [TCP/IP Tutorial and Technical Overview](https://www.redbooks.ibm.com/redbooks/pdfs/gg243376.pdf)

**协议文档**:

- [RFC 1928: SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 9293: Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 768: User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [HTTP on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)

- DNS污染
- SNI
- IP封锁