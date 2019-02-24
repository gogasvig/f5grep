#!/usr/bin/env python2
'''Script that uses grep to search for a pattern in the configuration
files on all listed F5 BigIP servers.

Some code and ideas taken from:
        https://github.com/pexpect/pexpect/blob/master/examples/monitor.py
        https://github.com/pexpect/pexpect/blob/master/examples/topip.py

PEXPECT LICENSE

    This license is approved by the OSI and FSF as GPL-compatible.
        http://opensource.org/licenses/isc-license.txt

    Copyright (c) 2017, David Couture <dc@balr12.com>
    PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY
    PURPOSE WITH OR WITHOUT FEE IS HEREBY GRANTED, PROVIDED THAT THE ABOVE
    COPYRIGHT NOTICE AND THIS PERMISSION NOTICE APPEAR IN ALL COPIES.
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


PEXPECT LICENSE

    This license is approved by the OSI and FSF as GPL-compatible.
        http://opensource.org/licenses/isc-license.txt

    Copyright (c) 2012, Noah Spurrier <noah@noah.org>
    PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY
    PURPOSE WITH OR WITHOUT FEE IS HEREBY GRANTED, PROVIDED THAT THE ABOVE
    COPYRIGHT NOTICE AND THIS PERMISSION NOTICE APPEAR IN ALL COPIES.
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

'''

from __future__ import print_function


from argparse import ArgumentParser
import getpass
import logging
import os
import sys
from tempfile import NamedTemporaryFile as NTF

import pexpect


PASSWORD = '(?i)password'
BASH_PROMPT = r' [#\$] '
SSH_NEWKEY = '(?i)are you sure you want to continue connecting'
TMSH_PROMPT = r'# '

USING_TMSH = None

BIGIP_HOSTS = ('fqdn1',
               'fqdn2',)


def cmd_args():
    '''
    Process command line arguments.

    '''
    parser = ArgumentParser(
        description='Script to run grep against the BigIP config files.')

    parser.add_argument(
        '-E', '--extended-regexp', action='store_true',
        help='Interpret the pattern as an extended regular expression (ERE)')

    parser.add_argument(
        '-i', '--ignore-case', action='store_true',
        help='Ignore case distinctions in both the pattern and input files')

    parser.add_argument(
        '-ll', '--loglevel', type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level')

    parser.add_argument(
        'pattern', help='Look for a pattern in BigIP configuration files')

    return parser.parse_args()


def get_user_credentials_from_stdin():
    '''Get user credentials from stdin.

    Returns (user, password).

    '''
    default_user = os.getlogin()

    user = raw_input('F5 userid to use [{0}]? '.format(default_user))

    # Empty reply means use the default user.

    if user == '':
        user = default_user

    user_password = getpass.getpass('F5 password for {0}? '.format(user))

    return user, user_password


def setup_debug_log(args, host):
    '''If debugging is enable then create a debug log file object and
    return.

    '''
    fileobj = None

    # If debug is enabled then use temporary files as log files to
    # help debug pexpect/expect issues.  They will have to be manually
    # deleted.
    #
    # NOTE: Passwords will show up in clear text!  Debug on a
    # private system.

    if args.loglevel == 'DEBUG':
        fileobj = NTF(prefix='f5grep.py-{0}-'.format(host), delete=False)
        logging.debug('debug log: %s', fileobj.name)

    return fileobj


def ssh_grep(host, child, args):
    '''host: Hostname
    child: pexpect object
    args: command line arguments (including pattern)

    Use pexpect to run grep via an ssh session.

    "child" will be an already running ssh session.  Use the arguments
    passed on the command line to call grep and print out results to
    stdout.

    '''
    bigip_files = '/config/bigip.conf /config/partitions/*/bigip.conf'

    grep_cmd = ['grep']

    grep_cmd.append('--with-filename')
    grep_cmd.append('--no-messages')
    grep_cmd.append('--color=always')
    grep_cmd.append('--line-number')

    if args.extended_regexp:
        grep_cmd.append('--extended-regexp')

    if args.ignore_case:
        grep_cmd.append('--ignore-case')

    # Prepend '-e' to protect pattern in case it starts with a
    # dash and enclose pattern in quotes to protect it from the
    # shell.

    grep_cmd.append('-e')
    grep_cmd.append("'" + args.pattern + "'")

    grep_cmd.append(bigip_files)

    logging.debug('grep_cmd: %s', ' '.join(grep_cmd))

    child.sendline(' '.join(grep_cmd))
    child.expect(BASH_PROMPT)

    logging.debug('child.before: %s', child.before)
    logging.debug('child.after: %s', child.after)

    grep = child.before.split('\r\n')

    if len(grep) > 2:       # Found something.

        grep.pop(0)         # Remove first element.
        grep.pop()          # Remove last element.

        print("\nFound matches on {0}:\n\t{1}"
              .format(host,
                      '\n\t'.join(grep)))


def ssh_login(host, fileobj, user, password):
    '''host: Hostname use ssh to log into
    fileobj: pexpect logfile

    Use pexpect to try and login to host using ssh.

    '''
    child = pexpect.spawn('ssh {0}@{1}'.format(user, host))
    child.logfile = fileobj

    global USING_TMSH
    USING_TMSH = False

    while True:
        _index = child.expect([pexpect.EOF, pexpect.TIMEOUT, SSH_NEWKEY,
                               TMSH_PROMPT, PASSWORD, BASH_PROMPT])

        logging.debug("ssh_login::expect: _index=%d", _index)

        if _index in (0, 1):    # Timeout or EOF.
            logging.error('ERROR! could not login to %s@%s using SSH',
                          user, host)
            logging.debug("%s\n%s", child.before, child.after)
            logging.debug(str(child))
            sys.exit(1)
        elif _index == 2:       # Prompt to accept new ssh key.
            child.sendline('yes')
            continue
        elif _index == 3:       # TMSH prompt.

            # Switch to bash.

            child.sendline('bash')

            # Need to save this state because bash will be running
            # under tmsh and requires 2 levels of logouts.

            USING_TMSH = True
            continue
        elif _index == 4:       # Password prompt.
            child.sendline(password)
            continue
        elif _index == 5:       # Bash prompt.
            pass

        break

    # Set cols/rows to unlimited to disable paging and page breaks.

    child.sendline('stty cols 0 rows 0')
    child.expect(BASH_PROMPT)

    return child


def ssh_logout(child):
    '''child: pexpect object

    Use pexpect to exit the ssh session.

    '''
    child.sendline('exit')

    if USING_TMSH:
        child.expect(TMSH_PROMPT)
        child.sendline('quit')

    child.expect(pexpect.EOF)

    child.logfile = None


def main():
    '''Loop over all of the BigIP hosts and ssh to each one and run grep
    against the BigIP configuration files.

    '''
    args = cmd_args()

    logging.basicConfig(level=args.loglevel)

    user, password = get_user_credentials_from_stdin()

    # Force TERM to "xterm" to avoid "unknown term" error.

    os.environ["TERM"] = 'xterm'

    for host in BIGIP_HOSTS:
        logging.info('host: %s', host)

        fileobj = setup_debug_log(args, host)

        child = ssh_login(host, fileobj, user, password)

        ssh_grep(host, child, args)

        ssh_logout(child)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
