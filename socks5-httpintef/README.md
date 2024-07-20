Can be integrated into TLS MITM,
since tls.Conn and net.Conn are similar.

The difference is that in this project,
we use Gzip to decompress the data before sending it to the client proxy.
