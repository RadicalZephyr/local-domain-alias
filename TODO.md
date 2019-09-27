- Make a forked version of basic-http-server that can accept a socket
  passed by systemd
- Make this program have an option to generate a socket-activated
  systemd unit-file so that you can set up an alias for a project once
  and then just go to the webpage to start the docs server.

Probably make a single generic unit that can be enabled with
parameters like:

systemctl enable serve@docs.rs:7495

Other benefits of it being managed by systemd are not needing to
use the setuid bit on local-domain-alias (maybe?) because you would
put that call into the pre-exec of the systemd unit.

Then also make it so that the server quits gracefully after an
inactivity period. This can be fairly small even because systemd will
keep relaunching it when the socket gets opened.


---



What about the userspace un-privileged version?

It would be a single server process that is a DNS resolver and a
basic-http-server on-demand.  Then there would be a way to tell it new
pairs of alias and folder to serve. The port becomes irrelevant
because all the domain names are mapped to 127.0.0.1.  This means this
service does want to run with privileges so it can be running on port
80.
