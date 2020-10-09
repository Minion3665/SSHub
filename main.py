import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import hashlib
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
    @staticmethod
    def _auth(*args, **kwargs):
        pass

class Server(paramiko.ServerInterface):
    def __init__(self, mid_to_ip, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mid_to_ip = mid_to_ip

        self.machine = None
        self.allowed = []
        self.user = None
        self.event = threading.Event()

    def set_machine(self, mid):
        ip = self.mid_to_ip(mid) or False
        if not ip:
            self.machine = False
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
        print("Get allowed auths", self.allowed, self.machine)
        if self.allowed:
            return ",".join(self.allowed)
        if self.machine is None:
            part1, _, part2 = username.rpartition("@")
            self.user = part1 or part2
            mid = part1 and part2
            if not mid:
                return "keyboard-interactive"
            else:
                if self.set_machine(mid) == paramiko.AUTH_FAILED:
                    return ""
        elif self.machine is False:
            return ""
        try:
            self.machine._transport.auth_none(self.user)
        except paramiko.BadAuthenticationType as bat:
            self.allowed = bat.allowed_types
        else:
            return "none"
        return ",".join(self.allowed)

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
        print("Trying password", password)
        try:
            self.allowed = self.machine._transport.auth_password(self.user, password, fallback=False)
            print(self.allowed)
        except paramiko.BadAuthenticationType as bat:
            print(bat.allowed_types)
            self.allowed = bat.allowed_types
            return paramiko.AUTH_FAILED
        except paramiko.AuthenticationException:
            print("Password auth failed: bad password, hash was ", hashlib.sha256(password).hexdigest())
            self.allowed = []
            return paramiko.AUTH_FAILED
        except Exception as e:
            print(e)
        else:
            print("Password auth success", self.allowed)
            return paramiko.AUTH_PARTIALLY_SUCCESSFUL if self.allowed else paramiko.AUTH_SUCCESSFUL


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
    chan = t.accept(500)
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