A proxy with routing that use system command to get pid and cmdline, and then decide which proxy to use.

```
+---------+   +--------------+   +--------------+   +----------+
| User ->-+---+-> Proxy 1 ->-+---+-> Proxy 2 ->-+---+-> Server |
+---------+   +--------------+   +--------------+   +----------+
```