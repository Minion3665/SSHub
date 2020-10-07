import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback

import paramiko
from paramiko.config import SSH_PORT
from paramiko.py3compat import b, u, decodebytes

from binascii import hexlify
import getpass
import inspect
import os
import socket
import warnings
from errno import ECONNREFUSED, EHOSTUNREACH

from paramiko.agent import Agent
from paramiko.common import DEBUG
from paramiko.config import SSH_PORT
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.hostkeys import HostKeys
from paramiko.py3compat import string_types
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import (
    SSHException,
    BadHostKeyException,
    NoValidConnectionsError,
)
from paramiko.transport import Transport
from paramiko.util import retry_on_signal, ClosingContextManager


# setup logging
paramiko.util.log_to_file("sshub.log")
host_key = paramiko.RSAKey(filename="sshub_host.key")

print("Read key: " + u(hexlify(host_key.get_fingerprint())))


def get_machine_ip_by_id(mid):
    print(f"Getting machine IP by {mid}")
    ids_to_ips = {
        "dom0": ("clicksminuteper.net", 22)
    }
    return ids_to_ips.get(mid, None)

class Client(paramiko.SSHClient):
    def connect(self, hostname, username, port=SSH_PORT, timeout=None, sock=None):
        if not sock:
            errors = {}
            # Try multiple possible address families (e.g. IPv4 vs IPv6)
            to_try = list(self._families_and_addresses(hostname, port))
            for af, addr in to_try:
                try:
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    if timeout is not None:
                        try:
                            sock.settimeout(timeout)
                        except:
                            pass
                    retry_on_signal(lambda: sock.connect(addr))
                    # Break out of the loop on success
                    break
                except socket.error as e:
                    # Raise anything that isn't a straight up connection error
                    # (such as a resolution error)
                    if e.errno not in (ECONNREFUSED, EHOSTUNREACH):
                        raise
                    # Capture anything else so we know how the run looks once
                    # iteration is complete. Retain info about which attempt
                    # this was.
                    errors[addr] = e

            # Make sure we explode usefully if no address family attempts
            # succeeded. We've no way of knowing which error is the "right"
            # one, so we construct a hybrid exception containing all the real
            # ones, of a subclass that client code should still be watching for
            # (socket.error)
            if len(errors) == len(to_try):
                raise NoValidConnectionsError(errors)

        t = self._transport = Transport(
            sock,
        )
        t.use_compression(compress=compress)

        if self._log_channel is not None:
            t.set_log_channel(self._log_channel)
        if banner_timeout is not None:
            t.banner_timeout = banner_timeout
        if auth_timeout is not None:
            t.auth_timeout = auth_timeout

        if port == SSH_PORT:
            server_hostkey_name = hostname
        else:
            server_hostkey_name = "[{}]:{}".format(hostname, port)
        our_server_keys = None

        our_server_keys = self._system_host_keys.get(server_hostkey_name)
        if our_server_keys is None:
            our_server_keys = self._host_keys.get(server_hostkey_name)
        if our_server_keys is not None:
            keytype = our_server_keys.keys()[0]
            sec_opts = t.get_security_options()
            other_types = [x for x in sec_opts.key_types if x != keytype]
            sec_opts.key_types = [keytype] + other_types

        t.start_client(timeout=timeout)

        # If GSS-API Key Exchange is performed we are not required to check the
        # host key, because the host is authenticated via GSS-API / SSPI as
        # well as our client.
        server_key = t.get_remote_server_key()
        if our_server_keys is None:
            # will raise exception if the key is rejected
            self._policy.missing_host_key(
                self, server_hostkey_name, server_key
            )
        else:
            our_key = our_server_keys.get(server_key.get_name())
            if our_key != server_key:
                if our_key is None:
                    our_key = list(our_server_keys.values())[0]
                raise BadHostKeyException(hostname, server_key, our_key)

class Server(paramiko.ServerInterface):
    def __init__(self, mid_to_ip, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mid_to_ip = mid_to_ip

        self.machine = None
        self.user = None
        self.event = threading.Event()

    def set_machine(self, mid):
        ip = self.mid_to_ip(mid) or False
        if not ip:
            return paramiko.AUTH_FAILED
        try:
            self.machine = Client()
            self.machine.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.machine.connect(hostname=ip[0], username=self.user, port=ip[1] or SSH_PORT)
        except Exception as e:
            print(e)

        return paramiko.AUTH_PARTIALLY_SUCCESSFUL if self.machine else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def get_allowed_auths(self, username):
        print("Getting allowed auths")
        if self.machine is None:
            part1, _, part2 = username.rpartition("@")
            self.user = part1 or part2
            mid = part1 and part2
            if not mid:
                return "keyboard-interactive"
            else:
                if self.set_machine(mid) == paramiko.AUTH_FAILED:
                    return "none"
        elif self.machine is False:
            return "none"
        print(f"VMID captured as {self.machine}")
        return "password"

    def check_auth_interactive(self, username, _submethods):
        if not self.machine:
            query = paramiko.InteractiveQuery(
                name="Machine ID",
                instructions="What machine would you like to connect to?"
            )
            query.add_prompt("Enter your Machine ID", echo=True)
            return query

    def check_auth_interactive_response(self, responses):
        if not self.machine:
            return self.set_machine(responses[0])

    def check_auth_password(self, _, password):
        print("Password", password)
        return paramiko.AUTH_SUCCESSFUL


DoGSSAPIKeyExchange = True

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 2200))
except Exception as e:
    print("*** Bind failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print("Listening for connection ...")
    client, addr = sock.accept()
except Exception as e:
    print("*** Listen/accept failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

print("Got a connection!")

try:
    t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
    t.set_gss_host(socket.getfqdn(""))
    try:
        t.load_server_moduli()
    except:
        print("(Failed to load moduli -- gex will be unsupported.)")
        raise
    t.add_server_key(host_key)
    server = Server(get_machine_ip_by_id)
    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    # wait for auth
    chan = t.accept(20)
    if chan is None:
        print("*** No channel.")
        sys.exit(1)
    print("Authenticated!")

    server.event.wait(10)
    if not server.event.is_set():
        print("*** Client never asked for a shell.")
        sys.exit(1)

    chan.send("\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n")
    chan.send(
        "We are on fire all the time!  Hooray!  Candy corn for everyone!\r\n"
    )
    chan.send("Happy birthday to Robot Dave!\r\n\r\n")
    chan.send("Username: ")
    f = chan.makefile("rU")
    username = f.readline().strip("\r\n")
    chan.send("\r\nI don't like you, " + username + ".\r\n")
    chan.close()

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)