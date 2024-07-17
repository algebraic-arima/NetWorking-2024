# PPCA 2024 网络项目 

## 项目介绍

了解计算机网络的基本原理，设计并实现一个网络代理。

## 项目要求

基础要求: [简单代理服务器](base.md) [socks5-server](socks5-server)

任选实现:

- [透明代理](tun.md) [socks5-tproxy](socks5-tproxy) 4'
- [TLS 劫持](tls.md) 2'+[HTTP 捕获/修改/重放](replay.md) 3' [socks5-tlsinterf](socks5-tleinterf)
- [代理客户端](client.md) 1'
  - [分流规则](rules.md)
    - [按 socks 地址分流](rules-ip.md) [socks5-2proxy-socksdis](socks5-2proxy-socksdis) 1'
    - 按域名分流 [socks5-httptlsdis](socks5-httptlsdis)
      - [HTTP 分流](rules-http.md) 1'
      - [TLS 分流](rules-tls.md) 1'
    - [按程序分流](rules-program.md) [socks5-progdis](socks5-progdis) 1'
  - [多级代理](chain.md) 2'
- [UDP 代理](udp.md) [socks5-udp](socks5-udp) 1'
- [反向代理](reverse.md)
  - TCP 反向代理 1'
  - HTTP 反向代理 1'
- 自选选题 (请与助教联系)

建议第一周完成基础任务，后面三周中每周完成 2'–3' 的任务。

请务必提前规划好这些功能之间的相互作用, 并考虑这些相互作用对程序整体架构带来的影响! 建议实现之前先与助教讨论你的选题和大体实现思路。

以上的工作量仅仅是助教的估计; 如果认为此估计不合理，请及时向助教提出。

## 评分标准

ACM 班:

- 简单代理服务器 25%
- 自选功能
  - 实现共 6' 的功能可以得到 55%
  - 实现共 9' 的功能可以得到 65%
- Code review 20%

最多可以得到 110% 的分数。

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
