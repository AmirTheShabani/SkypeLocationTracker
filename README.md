# SkypeLocationTracker
Very simple script I made to make tracking down participants in a skype call easier. Some versions of skype do not allow the configuration of what ports to use during a call. This makes it harder to sniff packets and pinpoint a skype callers IP address.

This script simply sniffs all UDP traffic, and keeps track of how many packets come from which IP address. Being in a call means large amounts of traffic to one IP address, in most cases. The IP address with the most amount of packets is determined to be the call participant, and their general location is determined through a database (already provided, feel free to upgrade for better results).

