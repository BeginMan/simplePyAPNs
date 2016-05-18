# coding=utf-8
"""
desc..
    :copyright: (c) 2016 by fangpeng(@beginman.cn).
    :license: MIT, see LICENSE for more details.
"""
import json
import socket
import logging
import struct
import ssl
import binascii

logger = logging.Logger('simplyPyAPNs')

DEFAULT_CONNECTION_TIMEOUT = 10     # Default timeout for attempting a new connection
DEFAULT_WRITE_TIMEOUT = 10          # Default timeout for write socket
RETRY_COUNT = 3                     # Default retry count for write socket

NOTIFICATION_STRUCT_FORMAT = (
    '!',            # network big-endian
    'B',            # command
    'H',            # token length
    '32s',          # device token(binary)
    'H',            # payload length
    '%ds'           # payload data
)


class Payload(object):
    def __init__(self, alert, badge=1, sound='default', extra={}):
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.extra = extra
        self.default_payload = {
            'aps': {'alert': self.alert,
                    'badge': self.badge,
                    'sound': self.sound}
        }

    @property
    def payload(self):
        if self.extra:
            self.default_payload.update({'extra': self.extra})
        return self.default_payload


class APNs(object):
    def __init__(self, cert_file, key_file, env='push_sandbox'):
        super(APNs, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.env = env
        self.connection = None

    def get_connection(self):
        if not self.connection:
            self.connection = APNSConnection(self.cert_file, self.key_file, self.env)
        return self.connection

    def init_data(self, token=None, payload=None):
        if not token or not payload:
            raise ValueError("need token and payload")

        if isinstance(payload, (Payload,)):
            payload = payload.payload

        payload = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        token = token.replace(' ', '')
        hex_token = binascii.unhexlify(token)
        fmt = ''.join(NOTIFICATION_STRUCT_FORMAT) % len(payload)
        notification = struct.pack(fmt, 0, 32, hex_token, len(payload), payload)
        return notification

    def send(self, token=None, payload=None):
        notification = self.init_data(token, payload)
        is_fail = True
        has_try_count = 0
        while is_fail and has_try_count < RETRY_COUNT:
            try:
                result = self.get_connection().send(notification, )
                is_fail = False
            except Exception as ex:
                logger.error(ex)
                has_try_count += 1
                print("APNS send failed, has tried " + str(has_try_count) + "times.")

        if is_fail:
            return False

        return int(result) <= 293 or False

    def send_multi(self, tokens, payloads):
        # todo
        pass

    def feedback(self):
        # todo
        pass


class APNSConnection(object):
    ADDRESSES = {
        "push_sandbox": ("gateway.sandbox.push.apple.com", 2195),
        "push_prod": ("gateway.push.apple.com", 2195),
        "feedback_sandbox": ("feedback.sandbox.push.apple.com", 2196),
        "feedback_prod": ("feedback.push.apple.com", 2196)
    }

    def __init__(self, cert_file=None, key_file=None, env='push_sandbox'):
        super(APNSConnection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.env = env
        self.ssl_sock = None
        self._socket = None
        self.gateway_server = None
        self.feedback_server = None

    @property
    def get_gateway_address(self):
        self.gateway_server = APNSConnection.ADDRESSES.get(self.env)
        if self.gateway_server is None:
            raise ValueError("Unknown address mapping: {0}".format(self.env))
        return self.gateway_server

    def connection(self):
        gateway_server = self.get_gateway_address
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(DEFAULT_CONNECTION_TIMEOUT)
            self.ssl_sock = ssl.wrap_socket(
                sock=self._socket,
                certfile=self.cert_file,
                keyfile=self.key_file
            )
            self.ssl_sock.connect(gateway_server)
        except socket.timeout:
            pass
        except:
            raise
        return self.ssl_sock

    @property
    def get_connection(self):
        if not self.ssl_sock:
            self.connection()
        return self.ssl_sock

    def send(self, msg):
        print self.gateway_server
        return self.get_connection.write(msg)

    def read(self, n=None):
        return self.get_connection.read(n)

    def __del__(self):
        if self.ssl_sock:
            self.ssl_sock.close()
