#!/usr/bin/python
#
# pipe your mail.log into this script and look if it says NO for a line
# example: ./regex.py < testlog-short.txt
#
# Hans van Kranenburg <hans@knorrie.org>

import sys
import re
from time import strptime
from collections import defaultdict

# first of all, split into timestamp, hostname, program, pid, msg
regex_syslog_full = re.compile(
    r'(?P<timestamp>(\S+\s+\S+ \S+)) (?P<hostname>\S+) '
    '(?P<program>[^[:]+)(\[(?P<pid>[^]]+)\])?: (?P<msg>.*)')

regex = defaultdict(lambda: defaultdict(None))

# postfix/smtpd[24234]: warning: 192.0.43.10: hostname example.com verification
# failed: Name or service not known
# postfix/smtpd[24731]: warning: 192.0.43.10: address not listed for hostname
# example.com
regex['postfix/smtpd']['warning'] = re.compile(
    r'warning: ((?P<ip>.+): )?(?P<warning>.+)$')

# postfix/smtpd[<pid>]: connect from <host>[<ip>]
regex['postfix/smtpd']['connect'] = re.compile(
    r'connect from (?P<host>.+)\[(?P<ip>.+)\]')

# postfix/smtpd[31131]: setting up TLS connection from example.com[192.0.43.10]
# postfix/smtpd[31131]: Anonymous TLS connection established from
# example.com[192.0.43.10]: TLSv1 with cipher ADH-AES256-SHA (256/256 bits)
regex['postfix/smtpd']['tls'] = re.compile(r'.*TLS connection')

# postgrey: action=<action>, reason=<reason>, client_name=<host>|unknown,
# client_address=<ip>, sender=<from>, recipient=<to>
regex['postgrey']['action'] = re.compile(
    r'((?P<queueid>.+): )?action=(?P<action>.+), reason=(?P<reason>.+), '
    'client_name=((?P<host>\S+)|unknown)')

# postgrey: whitelisted: unknown[192.0.43.10]
regex['postgrey']['whitelist'] = re.compile(
    r'whitelisted: (?P<host>.+)\[(?P<ip>.+)\]')

# postgrey: cleaning up old logs...
regex['postgrey']['cleanup'] = re.compile(r'^cleaning')

# postfix/smtpd[<pid>]: <queueid>: reject: RCPT from <host>[<ip>]: <reason>
# from=<<from>> to=<<to>> proto=<proto> helo=<<helo>>
regex['postfix/smtpd']['reject'] = re.compile(
    r'(?P<queueid>.+): reject: RCPT from (?P<host>.+)\[(?P<ip>.+)\]: '
    '(?P<reason>.*) from=\<(?P<from>.+)\> to=\<(?P<to>.+)\> '
    'proto=(?P<proto>.+) helo=\<(?P<helo>.+)\>')

# postfix/smtpd[<pid>]: lost connection after EHLO from <host>[<ip>]
# postfix/smtpd[<pid>]: timeout after RCPT from <host>[<ip>]
regex['postfix/smtpd']['fail'] = re.compile(
    r'(lost connection|timeout after).+ from (?P<host>.+)\[(?P<ip>.+)\]')

# postfix/smtpd[<pid>]: disconnect from <host>[<ip>]
regex['postfix/smtpd']['disconnect'] = re.compile(
    r'disconnect from (?P<host>.+)\[(?P<ip>.+)\]')

# postfix/smtpd[<pid>]: <queueid>: client=<host>[<ip>]
regex['postfix/smtpd']['client'] = re.compile(
    r'(?P<queueid>.+): client=(?P<host>.+)\[(?P<ip>.+)\]')

# postfix/cleanup[<pid>]: <queueid>: message-id=<<msgid>>
regex['postfix/cleanup']['msgid'] = re.compile(
    r'(?P<queueid>.+): message-id=\<?(?P<msgid>[^>]+)\>?')

# postfix/cleanup[<pid>]: <queueid>: resent-message-id=<<msgid>>
regex['postfix/cleanup']['resent_msgid'] = re.compile(
    r'(?P<queueid>.+): resent-message-id=\<?(?P<msgid>[^>]+)\>?')

# postfix/qmgr[<pid>]: <queueid>: from=<<from>>, size=<size>, nrcpt=<nrcpt>
# (queue active)
regex['postfix/qmgr']['process'] = re.compile(
    r'(?P<queueid>.+): from=\<(?P<from>.*)\>, size=(?P<size>.+), '
    'nrcpt=(?P<nrcpt>.+) \(queue active\)')

# clamsmtpd: <someid>: accepted connection from: <ip>
regex['clamsmtpd']['connect'] = re.compile(
    r'(?P<someid>\w+): accepted connection from: (?P<ip>\S+)')

# clamsmtpd: <someid>: from=<from>, to=foo, status=<status>
# clamsmtpd: <someid>: from=<from>, to=foo, to=bar, status=<status>
regex['clamsmtpd']['process'] = re.compile(
    r'(?P<someid>\w+): from=(?P<from>.+), .*status=(?P<status>.+)')

# spampd[<pid>]: processing message <<msgid>> for <<to>> ORCPT=rfc822;<to>
regex['spampd']['process'] = re.compile(
    r'processing message (\<(?P<msgid>.+)\>|\(unknown\)) '
    'for \<(?P<to>.+)\> (?P<orcpt>.+)')

# spampd[<pid>]: clean message (<<msgid>>|(unknown)) (<score>/<threshold>)
# from <<from>> for <<to>> ORCPT=rfc822;<to> in <time>s, <bytes> bytes.
# spampd[<pid>]: identified spam (<<msgid>>|(unknown)) (<score>/<threshold>)
# from <<from>> for <<to>> ORCPT=rfc822;<to> in <time>s, <bytes> bytes.
regex['spampd']['identify'] = re.compile(
    r'(clean message|identified spam) (\<(?P<msgid>.+)\>|\(unknown\)) '
    '\((?P<score>[\d.-]+)/(?P<threshold>[\d.-]+)\) from \<(?P<from>.*)\> for '
    '\<(?P<to>.+)\> (?P<orcpt>.+) in (?P<time>[\d.]+)s, (?P<bytes>\d+) '
    'bytes.')

# spampd[23126]: skipped large message (331.798828125KB)
regex['spampd']['skip'] = re.compile(r'skipped large message')

# messages from spampd we're not interested in
regex['spampd']['spam'] = re.compile(
    r'.*(Couldn\'t unlink|Server closing|Process Backgrounded|'
    'SpamPD.*starting|Binding to TCP port|Setting gid to|Setting uid to)')

# postfix/smtp[<pid>]: connect to <host>[<ip>]:<port>: Connection timed out
# postfix/smtp[<pid>]: connect to <host>[<ip>]:<port>: Connection refused
regex['postfix/smtp']['connectfail_no_queueid'] = re.compile(
    r'connect to (?P<host>.+)\[(?P<ip>.+)\]:(?P<port>\d+): '
    '(?P<reason>.*(timed out|refused|).*)')

# postfix/smtp[22201]: 8433EB24: lost connection with
# mta5.am0.yahoodns.net[66.94.237.139] while performing the HELO handshake
regex['postfix/smtp']['lost_connection'] = re.compile(
    r'(?P<queueid>.+): lost connection with')

# postfix/smtp[<pid>]: certificate verification failed for
# <host>[<ip>]:<port>: untrusted issuer <issuer>
regex['postfix/smtp']['connectwarn'] = re.compile(
    r'certificate verification failed for '
    '(?P<host>.+)\[(?P<ip>.+)\]:(?P<port>\d+): (?P<reason>.+)')

# postfix/smtp[<pid>]: <queueid>: to=<<to>>, relay=(<host>[<ip>]:<port>|none),
# delay=<delay>, delays=<2.7/0.01/0.05/0.07>, dsn=<2.0.0>, status=<status>
# (<reason>)
regex['postfix/smtp']['send'] = re.compile(
    r'(?P<queueid>.+): to=\<(?P<to>.+)\>, '
    'relay=((?P<host>.+)\[(?P<ip>.+)\]:(?P<port>.+)|none), '
    'delay=(?P<delay>.+), delays=(?P<delays>.+), '
    'dsn=(?P<dsn>.+), status=(?P<status>.+) \((?P<reason>.+)\)')

# postfix/smtp[5652]: CE4824F74: enabling PIX workarounds: disable_esmtp
# delay_dotcrlf for example.com[192.0.43.10]:25
regex['postfix/smtp']['pix'] = re.compile(
    r'(?P<queueid>.+): enabling PIX workarounds')

# postfix/smtp[<pid>]: <queueid>: host <host>[<ip>] said: 450 4.1.1
# a@example.com: Recipient address rejected: unverified address: Address
# verification in progress (in reply to RCPT TO command)
regex['postfix/smtp']['xyz'] = re.compile(
    r'(?P<queueid>.+): host (?P<host>.+)\[(?P<ip>[^]]+)\] said: '
    '(?P<status>\d+) (?P<dsn>[\d.]+) (?P<reason>.+)')

# postfix/qmgr[27372]: 7C7C91BE0: removed
regex['postfix/qmgr']['removed'] = re.compile(r'(?P<queueid>.+): removed')

# postfix/anvil[24062]: statistics: max connection count 1 for (smtp:x.y.z.a)
# at Dec 25 12:28:15
# postfix/anvil[24062]: statistics: max connection rate 1/60s for
# (smtp:x.y.z.a) at Dec 25 12:28:15
# postfix/anvil[24062]: statistics: max cache size 3 at Dec 25 12:33:20
regex['postfix/anvil'][''] = re.compile(r'statistics: ')

# postfix/pickup[22773]: F15C920BA: uid=0 from=<root>
regex['postfix/pickup'][''] = re.compile(
    r'(?P<queueid>.+): uid=(?P<uid>\d+) from=\<(?P<from>.+)\>')

# postfix/local[6270]: 3E73822B2: to=<<to>>, orig_to=<<orig_to>>,
# relay=local, delay=2.3, delays=2.2/0.01/0/0.02, dsn=2.0.0, status=sent
# (forwarded as 498281C23)
regex['postfix/local'][''] = re.compile(
    r'(?P<queueid>.+): to=\<(?P<to>.+)\>, orig_to=\<(?P<orig_to>.+)\>, '
    'relay=local, delay=(?P<delay>.+), delays=(?P<delays>.+), '
    'dsn=(?P<dsn>.+), status=(?P<status>.+) \((?P<reason>.+)\)')

# postfix/bounce[28295]: 065E52446: sender non-delivery notification: B1E4B260F
regex['postfix/bounce'][''] = re.compile(
    r'(?P<queueid>.+): sender (non-)?delivery notification: '
    '(?P<bouncequeueid>.+)')

# postfix/verify[22924]: cache /var/lib/postfix/verify_cache.db full cleanup:
# retained=611 dropped=0 entries
# postfix/verify[14210]: close database /var/lib/postfix/verify_cache.db: No
# such file or directory
regex['postfix/verify'][''] = re.compile(
    r'(close database|cache.+ cleanup)')

# nullmailer[6179]: smtp: Succeeded: 250 2.0.0 Ok: queued as 162604848
regex['nullmailer']['send'] = re.compile(
    r'smtp: Succeeded: 250 2\.0\.0 Ok: queued as (?P<queueid>.+)')

# messages from nullmailer we're not interested in:
# nullmailer[933]: Delivery complete, 0 message(s) remain.
# nullmailer[933]: Sent file.
# nullmailer[933]: Rescanning queue.
# nullmailer[933]: Trigger pulled.
regex['nullmailer'][''] = re.compile(
    r'(Delivery complete|Sent file|Rescanning queue|Trigger pulled)')

if __name__ == '__main__':
    for line in iter(sys.stdin.readline, ""):
        # timestamp, hostname, program, pid, msg
        logline = regex_syslog_full.match(line).groupdict()
        # XXX: no year in syslog lines
        timestamp = strptime(logline['timestamp'], "%b %d %H:%M:%S")
        for expression in regex[logline['program']].itervalues():
            match = expression.match(logline['msg'])
            if match:
                print("YES %s %s" % (logline, match.groupdict()))
                print
                break
        if match is None:
            print("NO could not match: %s %s" % (logline, line))
            print
