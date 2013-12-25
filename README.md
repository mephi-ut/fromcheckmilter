fromcheckmilter
===============

Disallows mail with unresolvable domain name in value of "From" field.

The milter just parses domain name from "From" field and tries to get MX/A
record of it. On failure it sends back "TEMPFAIL".

"TEMPFAIL" is used instead of "REJECT" to save good letters in case of
DNS problems. However if it's not DNS problem, just bad letter, it will get
"TEMPFAIL" forever and will never pass through.

Mail filtered by "-m" option is "REJECT"-ed (not "TEMPFAIL"-ed).

Any questions?
 - IRC: ircs://irc.campus.mephi.ru/#mephi,xai,xaionaro
 - email: <dyokunev@ut.mephi.ru> 0x8E30679C


options
-------

 - -p /path/to/unix/socket - path to unix socket to communicate with MTA.
 - -t timeout - timeout in seconds of communicating with MTA.
 - -m - check "MAIL FROM" value and require domains of "MAIL FROM" and "From"
to be similar ("MAIL FROM" should be substring of "From" or vice versa).
 - -M - don't reject mail with unsimilar "MAIL FROM" and "From". Just add
header "X-FromChk-Milter-MailFrom: mismatch" instead.
 - -h - help


example
-------

- from-check-milter[19042]: E77192FE8F9: Unable to resolve MX-record of domain name "pRYuvxQansRNx.net". Unusual for mail server.
- from-check-milter[19042]: E77192FE8F9: Unable to resolve domain name "pRYuvxQansRNx.net" from "From" value: "=?utf-8?B?0JzQtdC00LjQsCDRgdC70YPQttCx0LA=?= <higGpDA@pRYuvxQansRNx.net". Answering TEMPFAIL.
