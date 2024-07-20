# Transparent Proxy 

A toy tproxy implementation based on gid.

To run, first restart ubuntu and run [tp.sh](tp.sh). Then run `code`.

After that, launch another terminal, `su` in another user `pusr` and run `curl`.

All the traffic from user `pusr` will be redirected to the 8080 port that tproxy listens on.

