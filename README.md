maillogpoc
==========

Mail log analyzer PoC (Proof of Concept)

Goal: write a program that receives logging lines from postfix, spampd,
postgrey, clamsmtp etc, combining different log lines into an information
object per email, describing the way it 'traveled' through our mail systems.

Store all information somewhere, so other mail servers can do the same trick
and search for existing information, appending it as soon as they see the
same mail getting forwarded to them. (so the story of an email could be
'eventually' complete as information trickes in, maybe in random order...
interesting...) Or, syslog all messages to a single location and run only
one instance there. Same issue remains, order in which syslog messages arrive
from different hosts is not predictable.

Also see testlog-short-description.txt ... it seems quite hard to do this...
There's an afwul lot of state that needs to be kept to be able to match
lines and map them onto previous ones. The example shows a single email which
arrives and traveles through the clamsmtp and spampd after-queue filters.
This also simulates the same result that could occur when this message is
bounced between three smtp servers which are all logging to a central syslog
location, where we're analyzing the log stream... well... in which case
the log messages could arrive even more out-of-order so keeping state gets
even more difficult.

Step 1: write a bunch of regexes that can completely read a day to day
mail.log from any of our mail servers. The regexes extract information from
syslog lines that will help us relating them to other log lines.

-> See regex.py

Step 2: ...

Hans van Kranenburg <hans@knorrie.org>
