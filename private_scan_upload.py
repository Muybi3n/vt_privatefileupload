#!/usr/bin/env python3

__version__ = '1.8.2'

#
# WELCOME!
# --------
#
# If you are reading this file you are probably a Software Engineer looking for
# some examples of how to use the VirusTotal API for private file scanning. You
# are in the right place, this file is for you.
#
# This little program will guide you through the steps required for scanning a
# file privately in VirusTotal, and will teach you how to extract some useful
# information from the generated reports. Ready to start?
#
# REQUIREMENTS
# ------------
#
# This program has very little requirements, but still it has some. The first
# one is Python 3, of course, because this is a Python 3 program. Python 2 is
# not supported.
#
# It also depends on some libraries, some of them are standard libraries that
# come already with Python, like the following ones:
#
# EXAMPLE USAGE
#
#  1. Scan a file: ./privscan.py --network-enabled installer.exe
#  2. Open URL in explorer:
#     echo "explorer http://youtube.com" > youtube.bat && \
#         ./privscan.py  --network-enabled  youtube.bat

#
# But the program also depends on third-party libraries that must be installed
# separately. For installing those libraries you can use:
#
# pip3 install requests rich
#
# But don't worry, if you try to run this program without installing the required
# libraries it will tell you what to install.
#
try:
  import argparse
  import base64
  import datetime
  import hashlib
  import json
  import os
  import re
  import time
  import sys
  from tkinter import filedialog
  from pkg_resources import require
  import urllib3
  import pdb
  import threading
  import subprocess
  from tqdm import tqdm
  import vt
  import requests
  from requests.adapters import HTTPAdapter
  from urllib3.util.retry import Retry
  from rich.console import Console
  from rich.prompt import Confirm
  from rich.prompt import Prompt
  from rich.table import Table
  from rich.text import Text
  from rich.tree import Tree
  from rich.style import Style
  from rich import box
  from datetime import datetime
  import enum
except ModuleNotFoundError:
  print('\nATENTION!\n')
  print('Some of the libraries required by this program are not currently installed.')
  print('Please run "pip3 install rich requests" for installing them.')
  sys.exit(1)

# Disable warning in case the user specifies the --skip-ssl-verification flag.
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)

#
# GLOBALS
# -------
#
# Here comes some global definitions. Nothing important here, just a few things
# that are used in multiple places of the code.
#
SPINNER = {'spinner': 'dots', 'spinner_style': 'bright_yellow'}
LEFT_COLUMN_MIN_WIDTH = 15
CONSOLE_WITH = 130

CSV_HEADERS = [
    "HASH", " Meaningful_Name", "File_Type", "Detection_Score",
    "First_Seen_Date", "Last_Analysis_Date",
    "Suggest_Threat_Label", "Sandbox_Verdicts_Zenbox", "Asset_Sandbox_Verdicts_C2AE",
    "AV_Scanning_Results_Microsoft", "AV_Scanning_Results_Clamav", "AV_Scanning_Results_Fortinet",
    "AV_Scanning_Results_Sophos", "Contacted_ITW", "Embedded_Urls", "Tags", "FILE_URL"
]

FAILED_CSV_HEADERS = ["SCAN_ID"]

console = Console(width=CONSOLE_WITH)
file_success_count = 0

api_key = ""
#output file for extracted file
output_dir = ""
csv_export_file_path = ""
scan_file_ids = []
#this maintains a link between scan_id and hash
#scan_and_hash_file_ids = dict()
#Premium account allows only 25 api calls/minute for private scan
batch_size = 25
#
# VERSION CHECK
# -------------
#
# If there is a new version of the script it will automatically update it.
#


def version_update(verify_ssl_cert=True):
  response = requests.get(
      'https://storage.googleapis.com/vtcdn/api-scripts/privscan.py',
      verify=verify_ssl_cert)
  if response.status_code != 200:
    console.print('Unable to check the last version of the script')
    return False

  content = response.content.decode()
  last_version = re.search(r'^__version__ = \'([^\']*)\'$', content, re.M)
  if last_version and last_version.group(1) == __version__:
    return False

  console.print('New version available, updating script...')
  try:
    with open(__file__, 'w', encoding='utf-8') as f:
      f.write(content)
  except Exception as e:
    console.print('Error updating the script: %s' % e)
    return False
  return True


def proxy_check():
  try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    requests.get('https://www.virustotal.com', verify=True)
    return False
  except requests.exceptions.SSLError:
    return True

#
# UTILITY FUNCTIONS AND CLASSES
# -----------------------------
#
# Here we start defining some utility functions and classes that are going to
# be useful later on. One of such functions is `get_key`, which allows to extract
# a specific field from a dictionary that contains other nested dictionaries.
#
# For example, given the following dictionary:
#
#  {
#    'foo': {
#      'bar': {
#        'baz': <some value>
#      }
#    }
#  }
#
#  get_key will return <some value> when asked for the key "foo.bar.baz" where
#  the dot (.) is used as key separator. If key is "foo.bar" the result is:
#
#  {
#    'baz': <some value>
#  }
#
#  This function is very useful because the JSON responses returned by the
#  VirusTotal API usually consist on heavily-nested dictionaries, and get_key
#  simplifies the process of extracting values from them.
#


def get_key(dictionary, key, default_value=None):
  """Get value from nested dictionaries.

  Args:
    dictionary: A dictionary with possibly nested dictionaries.
    key: A string with the full key to retrieve.
    default_value: Value returned if the key is not found.

  Returns:
    The value stored in the provided key.

  Raises:
    KeyError: if the provided key is not valid.
  """
  dictionary = dictionary or {}
  keys = key.split('.')
  field_name = keys.pop()
  for k in keys:
    if k not in dictionary:
      return default_value
    dictionary = dictionary[k]
    if not isinstance(dictionary, dict):
      raise KeyError('"%s" is not a dictionary' % k)
  return dictionary.get(field_name, default_value)
#
# Generates object ID for an URL. The ID generated can be used in API calls that
# expect an URL ID like GET /urls/<id>.
#


def url_id(url):
  return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
#
# ApiClient is another helper class used in this program. It's a very simple
# class that facilitates making GET and POST requests to the VirusTotal API.
#
# This class sets the necessary HTTP headers on each request, like for
# example the "X-Apikey" header that contains your API key and allows VirusTotal
# identifying the user making the call.
#
# It also sets the "Accept-Encoding: gzip" header, letting know the VirusTotal
# API servers that they can respond with gzip-compressed data, reducing the
# used bandwith and the latency of your requests. Finally, it also sets the
# "User-Agent" agent header to "Private Scan Sample Script; gzip". The important
# detail about the user agent is the "; gzip" part at the end. This is an
# additional requirement by Google AppEngine (the service that hosts the
# VirusTotal API), which refuses to send gzip-compressed to clients that don't
# send the "gzip" string somewhere in the user agent. For more details see:
# https://stackoverflow.com/questions/8471681/appengine-gzip-compressing
#


class ApiClient:
  def __init__(self, apikey, verify=True):
    self._apikey = apikey
    self._host = 'https://www.virustotal.com'
    self._verify = verify
    self._headers = {
        'X-Apikey': self._apikey,
        'Accept-Encoding': 'gzip',
        'User-Agent': 'Scan Sample Script; gzip'}
     
  def get(self, path, **kwargs):
    if path.startswith('http'):
      url = path
    else:
      url = self._host + path
    if 'timeout' not in kwargs:
      kwargs['timeout'] = 20  # Set default timeout to 20 seconds.
    
    response = requests.get(
        url, headers=self._headers, verify=self._verify, **kwargs)
            
    if response.status_code != 200:
      raise Exception('Error %d: %s' % (response.status_code, response.text))
    return response

  def post(self, path, **kwargs):
    if path.startswith('http'):
      url = path
    else:
      url = self._host + path
    if 'timeout' not in kwargs:
      kwargs['timeout'] = 20  # Set default timeout to 20 seconds.
    response = requests.post(
        url, headers=self._headers, verify=self._verify, **kwargs)
            
    if response.status_code != 200:
      raise Exception('Error %d: %s' % (response.status_code, response.text))
    return response

# compute_sha256 is a small function that simply calculates the SHA-256 of
# a local file. We use the file's SHA-256 for checking if you already scanned
# the file privately in the past.
#


def compute_sha256(file_path):
  with open(file_path, 'rb') as fin:
    file_hash = hashlib.sha256(fin.read()).hexdigest()
  return file_hash
#
# scan_file is the function that sends a file to be scanned privately by
# VirusTotal. This is a two step process, in the first step we get an upload
# URL from the /api/v3/private/files/upload_url endpoint, and in the second
# step we upload the file to the received URL. This is required only for files
# larger than 32MB, for smaller files you can post them directly to
# /api/v3/private/files, but we do the two steps process for all files
# regardless of their size for homogeneity.
#
# The response from GET /api/v3/private/files/upload_url looks like:
#
#  {
#    'data': '<the upload URL>'
#  }
#
# The file is POSTed to the obtained URL together with two additional
# arguments: disable_internet and command_line. The first one must be either
# "true" or "false", and indicates whether the file will be detonated in
# a sandbox with Internet connectivity or not, while the second one is the
# string that will be passed to the file as command-line arguments while
# being executed.
#
# This function returns as soon as the file is uploaded and returns the
# identifier for the scan operation. This identifier can be used later on
# for obtaining information about how the scan's progress.
#


def scan_file(client, file_path, sandboxes_disabled=False,
              network_enabled=False, cmd_line='', zip_password=None):
  """Sends a file to be scanned by VirusTotal privately.

  Args:
    client: An instance of ApiClient.
    file_path: Path to the file that will be.
    sandboxes_disabled: If True, the file is not detonated in sandboxes.
    network_enabled: If True, enables network connectivity while detonating
       the file in a sandbox.
    cmd_line: Command-line arguments passed to the file while executing it.
    zip_password: Password used to unzip the file.

  Returns:
    The scan identifier.
  """
  # Obtain an upload URL that will be used for uploading the file.
  response = client.get('/api/v3/private/files/upload_url')
  #response = client.get('/api/v3/files/upload_url')
  url = response.json()['data']
  file_name = os.path.basename(file_path)

  # POST the file to the previously obtained URL.
  with open(file_path, 'rb') as fin:
    files = {
        'file': (file_name, fin),
    }
    data = {
        'disable_sandbox': str(sandboxes_disabled).lower(),
        'enable_internet':  str(network_enabled).lower(),
        'command_line': cmd_line}
    if zip_password is not None:
      data['password'] = zip_password

    response = client.post(url, files=files, data=data, timeout=120)
    scan_id = response.json().get('data', {}).get('id')
  return scan_id


def do_scan(file_name, client, args, progress_bar):
    try:
        filePath = os.path.join(args.output_dir, file_name)
        size = get_file_size(filePath, SIZE_UNIT.MB)
        if size > 200:
          console.print(
              f"File [red]{file_name}[/red] is too big (> 200 MB) and will be skipped.")
          return
        #sha256_item = compute_sha256(filePath)
    except FileNotFoundError as e:
        console.print(e)
        sys.exit(1)

    # Upload the file to VirusTotal and start the scanning.
    #console.print(f'Uploading file [yellow]{file_name}[/yellow] to VirusTotal for private scanning...')
    scan_id = scan_file(
        client,
        filePath,
        args.sandboxes_disabled,
        args.network_enabled,
        args.cmd_line,
        args.zip_password)

    progress_bar.update(1)
    if scan_id:
      #console.print(f"Successfully uploaded [green]{file_name}[/green]")
      global file_success_count
      file_success_count += 1
      #scan_file_ids.append(scan_id)
    else:
       console.print(f"Failed to upload [red]{file_name}[/red]")


# Enum for size units
class SIZE_UNIT(enum.Enum):
   BYTES = 1
   KB = 2
   MB = 3
   GB = 4


def convert_unit(size_in_bytes, unit):
   """ Convert the size from bytes to other units like KB, MB or GB"""
   if unit == SIZE_UNIT.KB:
       return size_in_bytes/1024
   elif unit == SIZE_UNIT.MB:
       return size_in_bytes/(1024*1024)
   elif unit == SIZE_UNIT.GB:
       return size_in_bytes/(1024*1024*1024)
   else:
       return size_in_bytes


def get_file_size(file_name, size_type=SIZE_UNIT.BYTES):
   """ Get file in size in given unit like KB, MB or GB"""
   size = os.path.getsize(file_name)
   return convert_unit(size, size_type)


def get_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
        This script demonstrates the use of the VirusTotal Private Scanning API.

        Files passed to this script will be scanned privately, and you'll get back a resume
        of the scan results.

        You need a VirusTotal API key to use this script, which can be passed either with the
        --api-key argument or through the VT_API_KEY environment variable.

        The scanned file will be detonated in a sandboxed environment, unless the argument
        --sandboxes-disabled is set. This environment doesn't have network connectivity by
        default. You can enable network connectivity by using the --network-enabled argument.

        Also, you can provide command-line arguments that will be passed to the file while
        being executed in a sandboxed environment by using the --cmd-line option.
        ''')

    parser.add_argument(
        '--api-key',
        help='your VirusTotal API key',
        required=False,
        default='')

    parser.add_argument(
        '--sandboxes-disabled',
        help='don\'t detonate in sandboxes, only apply other characterization tools',
        action='store_true',
        default=False)

    parser.add_argument(
        '--network-enabled',
        help='enables network connectivity while detonating the file in a sandbox',
        action='store_true',
        default=False)

    parser.add_argument(
        '--cmd-line',
        help='command line passed to the scanned file while executed in sandboxes',
        required=False,
        default='')

    parser.add_argument(
        '--disable-autoupdate',
        help='do not check and autoupdate this script',
        action='store_true',
        default=False)

    parser.add_argument(
        '--zip-password',
        help='password used to unzip the file and scan the contained file',
        required=False,
        default=None)

    parser.add_argument(
        '--skip-ssl-verification',
        help='skips the SSL certificates verification',
        action='store_true',
        default=True)
    
    parser.add_argument(
        '--output-dir',
        help='output folder of csv file, by default same folder with uploaded files',
        required=False,
        default=None)

    args = parser.parse_args()

    return args


def get_client(args):

    if not args.skip_ssl_verification and proxy_check():
        if not Confirm.ask(
            '[red]❯[/red] The SSL certificate received from virustotal.com is not '
            'valid. If you are behind\n  a proxy server this is expected and you '
            'can continue. However, this could also\n  mean that your connection '
            'is being intercepted by an attacker.\n\n  In the future you can use '
            'the --skip-ssl-verification flag for avoiding this question again.'
            '\n\n  Do you want to continue?',
                default=False):
            sys.exit(1)
        console.print()
        args.skip_ssl_verification = True

    #if not args.disable_autoupdate and version_update(
    #        verify_ssl_cert=not args.skip_ssl_verification):
        # Restart the script with the new updated version.
    #   os.execv(sys.executable, ['python'] + sys.argv)

    if not os.path.isdir(args.output_dir):
        console.print('The specified path is not a directory')
        sys.exit(1)

    api_key = args.api_key or os.environ.get("VT_APIKEY")

    return ApiClient(api_key, verify=not args.skip_ssl_verification)


def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        for file in files:
            yield os.path.join(root, file)


def upload_files(file_list, client, args):
    if len(file_list) == 0:
        console.print("[red]There is no file to upload.[/red]")
        return

    console.print("[yellow]Uploading files...[/yellow]")

   # Initialize the progress bar with the total number of files
    progress_bar = tqdm(total=len(file_list))

    start = datetime.now()
    threads = []
    # Iterate over the files and process each one
    for i in range(0, len(file_list), batch_size):
      #Process 1 batch at a time
      batch_file_list = file_list[i:i+batch_size]
      for file_path in batch_file_list:
          # Update the progress bar with each file processed
          #progress_bar.update(1)
          t = threading.Thread(target=do_scan, args=(file_path,), kwargs={
                              'client': client, 'args': args, 'progress_bar': progress_bar})
          t.start()
          threads.append(t)
          
      # Pause execution for 1 minute as the api allows 25 calls/minute
      if i+batch_size <= len(file_list):
        time.sleep(60)

    for t in threads:
        t.join()
    # Process the file here
    # record end time
    end = datetime.now()
    td = (end - start).total_seconds() * 10**3
    console.print()
    console.print(
        f"[green]Finished Uploading files!! There are total {file_success_count}/{len(file_list)} files successfully uploaded  for scanning in {td:.03f} ms[/green]")

    # Close the progress bar when done
    progress_bar.close()


def main(args):
   #extract_files(exe_file.name)
   file_list = [file for file in list_files(f"{args.output_dir}")]
   
   client = get_client(args)
   upload_files(file_list, client, args)
   

if __name__ == '__main__':
    try:
        args = get_arguments()
        api_key = args.api_key
        if not args.api_key:
            api_key = str(input("Enter API Key:"))
            while True:
                if not api_key:
                    api_key = Prompt.ask('\n[red]❯[/red] Enter your API key')
                if re.search('[0-9a-fA-F]{64}', api_key):
                    break
                else:
                    console.print('  "%s" is not a valid API key' % api_key)
                    api_key = None
            args.api_key = api_key

        print("Please choose the folder contains files need to upload")   
        output_dir = filedialog.askdirectory()
        if os.path.exists(output_dir) and os.path.isdir(output_dir):
            args.output_dir = output_dir
            main(args)
    except Exception as e:
        console.print(e)