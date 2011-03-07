#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# looputil.py
#
# Tool for working with loopia.se domains through their XMLRPC API.
#
# Author: Thomas Habets <habets@google.com>
#
# Copyright 2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Setup:
#   1) Create LoopiaAPI account (not the same as your loopia.se login account)
#   2) Create ~/.looputilrc as a two-line file. First line is
#      loopiaAPI username, second is the password.
#
#
# Running "batch mode":
#   $ ./looputil.py habets.se getrr www
#    record_id  type     ttl  prio       rdata
#     12753330     A     600     0  194.9.8.26
#
#   Time elapsed: 1.252s
#   $
#
# Running interactive (with tab completion for commands):
#   $ ./looputil.py habets.se
#   loopia(habets.se)> getrr www
#    record_id  type     ttl  prio       rdata
#     12753330     A     600     0  194.9.8.26
#
#   Time elapsed: 1.522s
#   loopia(habets.se)> domain habets.co.uk
#
#   Time elapsed: 0.000s
#   loopia(habets.co.uk)> list
#   @
#   www
#
#   Time elapsed: 3.728s
#   loopia(habets.co.uk)>
#
#
import atexit
import calendar
import os
import re
import readline
import sys
import time
import xmlrpclib

RPC_URI = 'https://api.loopia.se/RPCSERV'

class Domain(object):
    """Backend to LoopiaAPI. No stdout output, only exception for errors."""

    def __init__(self, username, password, domain):
        self.username = username
        self.password = password
        self.domain = domain
        self.rpc = xmlrpclib.ServerProxy(uri=RPC_URI, encoding = 'utf-8')

    def getUnpaid(self, vat=True):
        """Get unpaid invoices."""
        reply = self.rpc.getUnpaidInvoices(self.username,
                                           self.password,
                                           vat)
        return reply

    def getDomain(self, domain=None):
        """Get domain info dictionary."""
        if domain is None:
            domain = self.domain
        reply = self.rpc.getDomain(self.username,
                                   self.password,
                                   domain)
        if not isinstance(reply, dict):
            raise Exception("RPC returned error: " + reply)
        return reply

    def delRR(self, name, record_id):
        """Delete RR by name,record_id."""
        reply = self.rpc.removeZoneRecord(self.username,
                                          self.password,
                                          self.domain,
                                          name,
                                          int(record_id))
        if reply != "OK":
            raise Exception("RPC returned error: " + reply)

    def getRR(self, name):
        """Get RR by name."""
        reply = self.rpc.getZoneRecords(self.username,
                                      self.password,
                                      self.domain,
                                      name)
        if reply in (['BAD_INDATA'],
                     ['RATE_LIMITED']):
            raise Exception("RPC returned error: " + reply[0])
        return reply

    def addSubdomain(self, name):
        """Add 'subdomain'. Need to do this once for all RR names."""
        reply = self.rpc.addSubdomain(self.username,
                                      self.password,
                                      self.domain,
                                      name)
        if reply != "OK":
            raise Exception("RPC returned error: " + reply)

    def delSubdomain(self, name):
        """Delete subdomain (including all RRs for it)."""
        reply = self.rpc.removeSubdomain(self.username,
                                         self.password,
                                         self.domain,
                                         name)
        if reply != "OK":
            raise Exception("RPC returned error: " + reply)


    def addRR(self, name, type, rdata, ttl=3600, priority=0, record_id=0):
        """Add RR for a subdomain. Subdomain must already exist.

        This call will succeed even if subdomain doesn't exist, and it will
        look fine in DNS, but it will look weird in the loopia DNS editor and
        zonefile exporter.
        """
        data = {
            'type': type,
            'ttl': ttl,
            'rdata': rdata,
            'priority': priority,
            'record_id': record_id,
            }
        reply = self.rpc.addZoneRecord(self.username,
                                       self.password,
                                       self.domain,
                                       name,
                                       data)
        if reply != "OK":
            raise Exception("RPC returned error: " + reply)

    def listRR(self):
        """List just the name of all RRs."""
        reply = self.rpc.getSubdomains(self.username,
                                       self.password,
                                       self.domain)

        if len(reply) and reply[0] in ('UNKNOWN_ERROR',
                                       'RATE_LIMITED'):
            raise Exception("RPC returned error: " + reply[0])
        return reply

    def listDomains(self):
        """List all domains in this Loopia account."""
        reply = self.rpc.getDomains(self.username,
                                    self.password)
        if reply[0] == 'UNKNOWN_ERROR':
            raise Exception("RPC returned error: " + reply[0])
        return reply

class Completer:
    """Autocomplete callback functor for interactive (CLI) mode."""

    def __init__(self, words):
        self.words = words

    def __call__(self, text, state):
        self.matches = [w for w in self.words
                        if w.startswith(text)]

        try:
            return self.matches[state] + " "
        except IndexError:
            return None

class Loopia(object):
    """Interactive Loopia API handler"""

    def __init__(self, username, password, domain=None):
        self.d = Domain(username, password, domain)
        self.callbacks = {'addrr':       self.cb_addrr,
                          'addsub':      self.cb_addsub,
                          'delrr':       self.cb_delrr,
                          'delsub':      self.cb_delsub,
                          'domain':      self.cb_domain,
                          'getdomain':   self.cb_getdomain,
                          'getunpaid':   self.cb_getunpaid,
                          'getrr':       self.cb_getrr,
                          'help':        self.cb_help,
                          'newrr':       self.cb_newrr,
                          'list':        self.cb_listrr,
                          'listdomains': self.cb_listdomains,
                          'zone':        self.cb_zone,
                          }

    def cb_delsub(self, cmd, name):
        """Delete subdomain.  Ex: delsub foo"""
        self.d.delSubdomain(name)

    def cb_addsub(self, cmd, name):
        """Add subdomain.  Ex: addsub foo"""
        self.d.addSubdomain(name)

    def cb_getdomain(self, cmd, domain=None):
        """Get domain info."""
        for k, v in sorted(self.d.getDomain(domain).iteritems()):
            print "%-20s %s" % (k, v)

    def cb_getunpaid(self, cmd, vat=True):
        """Get unpaid invoices."""
        for inv in sorted(self.d.getUnpaid()):
            print "{"
            print "  reference:  %(reference_no)s" % inv
            print "  items:     ",
            print "\n              ".join(item['product']
                                          for item in inv['items'])
            print "  expires:    %(expires)s" % inv
            print "  to pay:     %(to_pay)s" % inv
            print "  pay online: %(payonline)s" % inv
            print "}"

    def cb_addrr(self, cmd, name, type, rdata,
                 ttl=3600, priority=0, record_id=0):
        """Add RR.  Ex: addrr warez A 127.0.0.1"""
        self.d.addRR(name, type, rdata, ttl, priority, record_id)

    def cb_delrr(self, cmd, name, record_id):
        """Remove RR by name and record_id.  Ex: delrr foo 12345"""
        self.d.delRR(name, record_id)

    def cb_newrr(self, cmd, name, type, rdata):
        """Add RR for new name.  Ex: newrr warez A 127.0.0.1"""
        self.addsub(cmd, name)
        self.addrr(cmd, name, type, rdata)

    def cb_getrr(self, cmd, name):
        """Get RR.  Ex: getrr warez"""
        rrs = self.d.getRR(name)
        if len(rrs) == 0:
            return
        maxlen = str(min(47,
                         max([len(x['rdata'])
                              for x in rrs])))
        fmt = ("%(record_id)10s %(type)5s %(ttl)7s %(priority)5s  %(rdata)"
               + maxlen + "s")
        print fmt % ({
                     'record_id': 'record_id',
                     'type': 'type',
                     'ttl': 'ttl',
                     'priority': 'prio',
                     'rdata': 'rdata',
                     })
        print '\n'.join([(fmt % rr) for rr in rrs])

    def cb_listrr(self, cmd):
        """List RRs."""
        for rr in sorted(self.d.listRR(),
                         key=lambda x: _domreverse(x)):
            print rr

    def cb_domain(self, cmd, domain):
        """Change active domain."""
        return Domain(self.d.username, self.d.password, domain)

    def cb_listdomains(self, cmd):
        """List all domains for this account."""
        for cur in sorted(self.d.listDomains(),
                          key=lambda x: _domreverse(x['domain'])):
            print "%(domain)60s %(expiration_date)15s" % cur

    def cb_help(self, cmd):
        """Show help text."""
        for k,v in sorted(self.callbacks.iteritems()):
            print "\t%-15s %s" % (k,v.__doc__)

    def cb_zone(self, cmd):
        """Export as BIND zonefile."""
        def normal(name, rr):
            return name + "IN %(ttl)6s %(type)-5s %(rdata)s" % rr
        def MX(name, rr):
            return name + "IN %(ttl)6s %(type)-5s %(priority)s %(rdata)s" % rr
        print "$ORIGIN %s." % (self.d.domain)
        for name in sorted(self.d.listRR(),
                       key=lambda x: _domreverse(x)):
            if name == "@":
                name = ""
            else:
                name = name + "."
            for e in _resolve_any_to_text("%s%s" % (name, self.d.domain),
                                         'ns1.loopia.se', self.d.domain):
                print re.sub(r'(^|\.)%s. ' % (self.d.domain), ' ', e)

    def unknown_command(self, cmd, *parms):
        """Default command callback function."""
        print >>sys.stderr, "Unknown command '%s'" % (cmd)

    def runcmd(self, cmd, *parms):
        """Run callback for command."""
        cmd = cmd.lower()
        t = time.time()
        ret = self.callbacks.get(cmd, self.unknown_command)(cmd, *parms)
        print "\nTime elapsed: %.3fs" % (time.time() - t)
        return ret

    def cli(self):
        """Run command line. Return value should be exit status of script."""
        try:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(Completer(self.callbacks))

            histfile = os.path.join(os.environ["HOME"], ".looputil_history")
            readline.read_history_file(histfile)
        except IOError:
            pass
        atexit.register(readline.write_history_file, histfile)
        #readline.add_history("domain %s" % (self.d.domain))
        while True:
            try:
                line = raw_input("loopia(%s)> " % (self.d.domain))
            except EOFError, e:
                print
                return 0

            arr = line.strip().split()
            try:
                ret = self.runcmd(arr[0], *arr[1:])
            except KeyboardInterrupt, e:
                return 0
            except Exception, e:
                print e
            else:
                if arr[0] == 'domain':
                    self.d = ret

def _resolve_any_to_text(name, ns, dom):
    """Shell out to dig instead of using RPC because of RPC rate-limiting."""
    ret = []
    cmdline = ("dig +noadditional +noquestion +nocmd "
               "+nostats +nocomment %s any @%s | grep ^%s"
               % (name, ns, name))
    for line in os.popen(cmdline, "r"):
        line = re.sub(r'\s+', ' ', line).strip()
        line = re.sub(r'\.%s. ' % (dom), ' ', line)
        line = re.sub(r'^%s. ' % (dom), '@ ', line)
        line = "%-30s %6s %3s %6s %s" % tuple(re.split(r'\s+', line, 4))
        ret.append(line)
    return ret

def _domreverse(r):
    """Reverse domain name, for proper sorting.
    Input is string, output is list.

    www.foo.com -> [com, foo, www]"""
    r = r.split('.')
    r.reverse()
    return r

def main():
    user, pw = [x.strip()
                for x in open(os.path.join(os.environ["HOME"], ".looputilrc"))]

    dom = 'null'
    if len(sys.argv) > 1:
        dom = sys.argv[1]

    loopia = Loopia(user, pw, dom)

    if len(sys.argv) < 3:
        sys.exit(loopia.cli())

    cmd = sys.argv[2]
    parms = sys.argv[3:]
    loopia.runcmd(cmd, *parms)

if __name__ == '__main__':
    main()
