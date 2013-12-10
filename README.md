fromcheckmilter
===============

Disallows mail with unresolvable domain name in value of "From" field.

The milter just parses domain name from "From" field and tries to get MX/A
record of it. On failure it sends back "TEMPFAIL".

"TEMPFAIL" is used instead of "REJECT" to save good letters in case of
DNS problems. However if it's not DNS problem, just bad letter, it will get
"TEMPFAIL" forever and will never pass through.

Any questions?
 - IRC: ircs://irc.campus.mephi.ru/#mephi,xai,xaionaro
 - email: <dyokunev@ut.mephi.ru> 0x8E30679C


options
-------

 - -p /path/to/unix/socket - path to unix socket to communicate with MTA.
 - -t timeout - timeout in seconds of communicating with MTA.
 - -m - check "MAIL FROM" value and require that domains of "MAIL FROM" and
"From" should be equal.
 - -h - help

