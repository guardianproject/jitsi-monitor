#!/usr/bin/env python3

import collections
import json
import os
import re
import requests
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import yaml
from datetime import datetime
from urllib.parse import urlparse

def _requests_get(url, allow_redirects=False, headers=dict()):
    if 'CI_PAGES_URL' in os.environ:
        headers['User-Agent'] = os.getenv('CI_PAGES_URL')
    else:
        headers['User-Agent'] =  'https://gitlab.com/guardianproject/jitsi-monitor'
    return requests.get(url, timeout=60,
                        allow_redirects=allow_redirects, headers=headers)


def _get_new_entry():
    d = collections.OrderedDict()
    d['config.js'] = collections.OrderedDict()
    return d


timeout = 60
timestamp = int(time.mktime(time.gmtime()))

with open('README.md') as fp:
    readme = fp.read()
teststr = '# Source Lists'
pattern = re.compile(r'^\s*\*\s*(.*)')

URL_REGEX = re.compile(b'https?://[a-z0-9.-]{3,}', re.IGNORECASE)

instances = set()
for line in readme[readme.find(teststr) + len(teststr) + 1:].split('\n'):
    if not line:
        continue
    url = pattern.sub(r'\1', line)
    r = _requests_get(url, allow_redirects=True)
    if r.status_code == 200:
        for url in URL_REGEX.findall(r.content):
            instances.add(url.decode().replace('http://', 'https://'))

if not instances:
    print("ERROR: the list of instances is empty!")
    sys.exit(1)

report = collections.OrderedDict()
for url in sorted(instances):
    starttime = datetime.now().timestamp()
    print('Checking', url)
    config_js = None
    try:
        r = _requests_get(url + '/config.js')
        if r.status_code == 200:
            if url not in report:
                report[url] = _get_new_entry()
            report[url]['headers'] = collections.OrderedDict(r.headers)
            if r.raw._connection and r.raw._connection.sock:
                report[url]['ip'] = r.raw._connection.sock.getpeername()[0]
            config_js = r.text
    except requests.exceptions.SSLError as e:
        if url not in report:
            report[url] = _get_new_entry()
        report[url][e.__class__.__name__] = str(e)
        if os.path.exists('config_js'):
            os.remove('config.js')
        os.popen('curl --silent --connect-timeout 60 %s/config.js > config.js' % url)
        if os.path.exists('config.js') and os.path.getsize('config.js') > 10:
            with open('config.js') as fp:
                config_js = fp.read()
            report[url]['fetchedWithCurl'] = True
    except Exception as e:
        print(type(e), e)
    if not config_js:
        continue
    config_js = re.sub(r'^\s*var\s+config\s*=\s*', r'', config_js, flags=re.MULTILINE)
    config_js = re.sub(r'\t', r'    ', config_js) # tab to space indent
    config_js = re.sub(r'};\s*', r'}', config_js) # no trailing semi-colon
    config_js = re.sub(r'([a-z0-9]):([0-9])', r'\1: \2', config_js) # fix sloppy key/value
    config_js = re.sub(r'^\s*//.*\n', r'', config_js, flags=re.MULTILINE)
    config_js = re.sub(r'\s*/\*.*\*/\s*', r'', config_js) # remove one line comment
    config_js = re.sub(r'^\s*/\*.*?\*/\s*$', r'', config_js, flags=re.DOTALL | re.MULTILINE)
    try:
        report[url]['config.js'] = yaml.load(config_js)
    except Exception as e:
        report[url]['config.js'][e.__class__.__name__] = str(e)

    report[url]['starttime'] = int(starttime)
    report[url]['duration'] = datetime.now().timestamp() - starttime

    hostname = urlparse(url).netloc
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                report[url]['TLS'] = ssock.version()
    except Exception as e:
        report[url]['TLS'] = str(e)

    if os.access('./tlsping', os.X_OK):
        p = subprocess.run(['./tlsping', '-json', hostname + ':443'],
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
        if p.returncode == 0:
            report[url]['tlsping'] = json.loads(p.stdout)
        else:
            report[url]['tlsping'] = p.stderr

    if shutil.which('nmap') is not None:
        p = subprocess.run(['nmap', '--script', 'ssl-enum-ciphers', '-p', '443', hostname],
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
        if p.returncode == 0:
            accept_pat = re.compile(r'^\|')
            yaml_pat = re.compile(r'^\|[_ ]( *)(.*:)')
            convert_pat = re.compile(r'^\| ( *)([^:]+)$')
            text = ''
            for line in p.stdout.split('\n'):
                if accept_pat.match(line):
                    line = yaml_pat.sub(r'\1\2', line)
                    line = convert_pat.sub(r'\1- "\2"', line)
                    text += line + '\n'
            if text:
                try:
                    data = yaml.safe_load(text)
                except Exception as e:
                    print(text)
                    print(e)
            if data:
                report[url]['ssl-enum-ciphers'] = data.get('ssl-enum-ciphers')
        else:
            report[url]['ssl-enum-ciphers'] = '<pre>' + p.stderr + '</pre>'

history = collections.OrderedDict()
os.makedirs('public', exist_ok=True)
if 'CI_PAGES_URL' in os.environ:
    r = _requests_get(os.getenv('CI_PAGES_URL') + '/report.json')
    if r.status_code == 200:
        history = r.json()
history[timestamp] = report
with open('public/report.json', 'w') as fp:
    json.dump(history, fp, sort_keys=True)

with open('public/index.html', 'w') as fp:
    fp.write('<!DOCTYPE html>\n<html lang="en"><head><title>Jitsi Monitor</title>')
    fp.write('<meta charset="utf-8"><link rel="stylesheet" href="main.css">')
    fp.write('</head><body><div class="site-wrapper"><header class="site-header">')
    fp.write('<a class="site-title" href="https://guardianproject.info">')
    fp.write('<img src="logo.png"><h1>%s</h1></a></header>' % os.getenv('CI_PROJECT_PATH'))
    fp.write('<div class="main-content-with-sidebar"><div class="article-area"><h2>Jitsi Monitor</h2>')
    fp.write('<p>Get the full history as JSON: <a href="report.json">report.json</a></p>')
    sourceurl = os.getenv('CI_PROJECT_URL')
    fp.write('<p>Source code:<a href="%s">%s</a></p>' % (sourceurl, sourceurl))
    try:
        from json2html import *
        fp.write(json2html.convert(json=report))
    except ImportError as e:
        print(type(e), e)
        fp.write('<pre>')
        fp.write(json.dumps(report, indent=2))
        fp.write('</pre>')
    fp.write('</div></div></div></body></html>')