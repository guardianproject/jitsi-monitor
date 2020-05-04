#!/usr/bin/env python3

import collections
import concurrent.futures
import ipaddress
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
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import parse_qs, urlparse


def var_name_from_file_name(name):
    """var name is camelCase, file name is snake_case"""
    no_ext = name[:-3]
    if '_' not in no_ext:
        return no_ext
    segments = no_ext.split('_')
    return ''.join([segments[0]] + [x.capitalize() or '_' for x in segments[1:]])


def get_jitsi_js_using_node(name, text):
    var_name = var_name_from_file_name(name)
    with tempfile.TemporaryDirectory() as tmpdir:
        js_path = os.path.join(tmpdir, name)
        with open(js_path, 'w') as fp:
            fp.write(text)
            fp.write(""";\nconsole.log(JSON.stringify(%s));\n""" % var_name)
        args = ['node', js_path]
        if shutil.which('firejail'):
            args = ['firejail', '--quiet', '--private', '--net=none'] + args
        p = subprocess.run(args, stdout=subprocess.PIPE)
    try:
        return json.loads(p.stdout)
    except json.decoder.JSONDecodeError as e:
        print(name, e.__class__.__name__, e)
        print(text)


def _get_jitsi_js_file(url, name):
    file_url = os.path.join(url, name)
    js = _get_url_contents(file_url)
    try:
        r = _requests_head(file_url)
        if r.status_code == 200:
            if url not in report:
                report[url] = _get_new_entry()
            report[url]['httpHeaders'] = collections.OrderedDict(r.headers)
            if r.raw._connection and r.raw._connection.sock:
                report[url]['ip'] = r.raw._connection.sock.getpeername()[0]
    except Exception as e:
        print(type(e), e, flush=True)
    if not js:
        return
    data = get_jitsi_js_using_node(name, js)
    if data:
        return data
    print('Fallback to parsing using regexs', flush=True)
    js = re.sub(r'^\s*var\s+[a-zA-Z0-9_]+\s*=\s*', r'', js, flags=re.MULTILINE)
    js = re.sub(r'\t', r'    ', js) # tab to space indent
    js = re.sub(r'};.*', r'}', js, flags=re.DOTALL) # end of the JSON-ish block
    js = re.sub(r'([a-z0-9]):([0-9])', r'\1: \2', js) # fix sloppy key/value
    js = re.sub(r'^\s*//.*\n', r'', js, flags=re.MULTILINE)
    js = re.sub(r"""\s*//[^'"]+""", r'', js)
    js = re.sub(r'\s*/\*.*\*/\s*', r'', js) # remove one line comment
    js = re.sub(r'^\s*/\*.*?\*/\s*$', r'', js, flags=re.DOTALL | re.MULTILINE)
    try:
        return yaml.safe_load(js)
    except Exception as e:
        return {e.__class__.__name__: str(e)}


def get_versions_from_index(url):
    text = _get_url_contents(url)
    if text:
        d = dict()
        soup = BeautifulSoup(text, 'lxml')
        for base in soup.find_all('base'):
            d['base'] = base.attrs.get('href')
        for stylesheet in soup.find_all('link', rel='stylesheet'):
            href = urlparse(stylesheet.attrs.get('href', ''))
            if href.query:
                q = parse_qs(href.query)
                if 'v' in q:
                    d[href.path] = q['v'][0]
        for script in soup.find_all('script'):
            src = urlparse(script.attrs.get('src'))
            q = parse_qs(src.query)
            if 'v' in q:
                d[src.path] = q['v'][0]
        return d


def run_nmap(url, hostname):
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
        data = None
        if text:
            try:
                data = yaml.safe_load(text)
            except Exception as e:
                print(text)
                print(e)
        if data:
            return (url, 'ssl-enum-ciphers', data.get('ssl-enum-ciphers'))
    else:
        return (url, 'ssl-enum-ciphers', '<pre>' + p.stderr + '</pre>')


def run_tcptraceroute(url, hostname):
    p = subprocess.run(['tcptraceroute', hostname, '443'],
                       stdout=subprocess.PIPE,
                       universal_newlines=True)
    if p.returncode == 0:
        entries = []
        for line in p.stdout.split('\n'):
            parts = line.strip().split()
            if not parts:
                continue
            entry = dict()
            try:
                int(parts[0])
            except ValueError:
                continue
            if parts[1] == '*':
                entry['hostname'] = '*'
            else:
                try:
                    ip = ipaddress.ip_address(parts[1])
                    entry['ip'] = str(ip)
                except ValueError as e:
                    entry['hostname'] = parts[1]
                    try:
                        ip = ipaddress.ip_address(parts[2].lstrip('(').rstrip(')'))
                        entry['ip'] = str(ip)
                    except ValueError as e:
                        print('%s: %s' % (e.__class__.__name__, e), flush=True)

            if len(parts) > 4:
                times = []
                for i in range(2, len(parts)):
                    try:
                        times.append(float(parts[i]))
                    except ValueError:
                        continue
                entry['timesInMs'] = times
            entries.append(entry)
        return (url, 'tcptraceroute', entries)


def _get_url_contents(url):
    try:
        r = _requests_get(url, allow_redirects=True)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(e.__class__.__name__, e)
        args = 'curl --silent --connect-timeout 60'.split() + [url]
        print('#', ' '.join(args))
        p = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        if p and p.stdout:
            return p.stdout.read().decode()


def _requests_get(url, allow_redirects=False, headers=dict()):
    if 'CI_PAGES_URL' in os.environ:
        headers['User-Agent'] = os.getenv('CI_PAGES_URL')
    else:
        headers['User-Agent'] =  'https://gitlab.com/guardianproject/jitsi-monitor'
    return requests.get(url, timeout=60,
                        allow_redirects=allow_redirects, headers=headers)


def _requests_head(url, allow_redirects=False, headers=dict()):
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

history = dict()
if 'CI_PAGES_URL' in os.environ:
    r = _requests_get(os.getenv('CI_PAGES_URL') + '/report.json')
    if r.status_code == 200:
        history = r.json()
for v in history.values():
    for url in v.keys():
        instances.add(url)

for line in readme[readme.find(teststr) + len(teststr) + 1:].split('\n'):
    if not line:
        continue
    url = pattern.sub(r'\1', line)
    try:
        r = _requests_get(url, allow_redirects=True)
        r.raise_for_status()
    except Exception as e:
        print(type(e), e)
        continue
    for url in URL_REGEX.findall(r.content):
        instances.add(url.decode().replace('http://', 'https://'))

if not instances:
    print("ERROR: the list of instances is empty!")
    sys.exit(1)

report = collections.OrderedDict()
executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(100, os.cpu_count() * 10))
futures = []
for url in sorted(instances):
    starttime = datetime.now().timestamp()
    print('Checking', url, flush=True)
    config_js = _get_jitsi_js_file(url, 'config.js')
    if not config_js:
        continue
    if url not in report:
        report[url] = _get_new_entry()
    report[url]['config.js'] = config_js
    logging_config_js = _get_jitsi_js_file(url, 'logging_config.js')
    if logging_config_js:
        report[url]['logging_config.js'] = logging_config_js
    versions = get_versions_from_index(url)
    if versions:
        report[url]['versions'] = versions

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
        futures.append(executor.submit(run_nmap, url, hostname))

    if shutil.which('tcptraceroute') is not None:
        futures.append(executor.submit(run_tcptraceroute, url, hostname))

for future in concurrent.futures.as_completed(futures):
    url = None
    key = None
    value = None
    try:
        result = future.result()
        if result and len(result) == 3:
            url, key, value = result
    except Exception as e:
        print('%r generated an exception for %s: %s' % (url, key, e))
    else:
        if url and key and value:
            report[url][key] = value


history[timestamp] = report
output = dict()
for k, v in history.items():
    output[int(k)] = v
os.makedirs('public', exist_ok=True)
with open('public/report.json', 'w') as fp:
    json.dump(output, fp, sort_keys=True)

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
        print(type(e), e, flush=True)
        fp.write('<pre>')
        fp.write(json.dumps(report, indent=2))
        fp.write('</pre>')
    fp.write('</div></div></div></body></html>')
