# coding=utf-8
"""
desc..
    :copyright: (c) 2016 by fangpeng(@beginman.cn).
    :license: MIT, see LICENSE for more details.
"""
import json
import socket
import logging
import ssl
import binascii
from datetime import datetime
from struct import pack, unpack

logger = logging.getLogger('simplyAPNs')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

DEFAULT_CONNECTION_TIMEOUT = 10     # Default timeout for attempting a new connection
DEFAULT_WRITE_TIMEOUT = 10          # Default timeout for write socket
RETRY_COUNT = 3                     # Default retry count for write socket
BUF_SIZE = 4096

NOTIFICATION_STRUCT_FORMAT = (
    '!',            # network big-endian
    'B',            # command
    'H',            # token length
    '32s',          # device token(binary)
    'H',            # payload length
    '%ds'           # payload data
)

FEEDBACK_STRUCT_FORMAT = (
    '!',            # network big-endian
    'I',            # four-byte time_t value
    'H',            # token length
    '32s',          # device token(binary)
)


class Payload(object):
    def __init__(self, alert, badge=1, sound='default', extra={}, content_available=False):
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.extra = extra
        self.default_payload = {
            'aps': {'alert': self.alert,
                    'badge': self.badge,
                    'sound': self.sound}
        }
        if content_available:
            self.default_payload['aps'].update(
                # support apns content-available
                # https://developer.xamarin.com/guides/ios/application_fundamentals/backgrounding/part_3_ios_backgrounding_techniques/updating_an_application_in_the_background/
                {'content-available': 1}
            )

    @property
    def payload(self):
        if self.extra:
            self.default_payload.update({'extra': self.extra})
        return self.default_payload

    def json(self, payload=None):
        if payload is None:
            payload = self.payload

        if isinstance(payload, (Payload,)):
            payload = payload.payload

        return json.dumps(payload, separators=(',', ':'),
                          ensure_ascii=False).encode('utf-8')

    def __repr__(self):
        attrs = ['alert', 'badge', 'sound', 'extra']
        args = ', '.join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)


class APNs(object):
    def __init__(self, cert_file, key_file, env='push_sandbox'):
        super(APNs, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.env = env
        self.connection = None
        self.feedback_connection = None

    def get_connection(self):
        """Gateway connection"""
        if not self.connection:
            self.connection = GatewayConnection(self.cert_file, self.key_file, self.env)
        return self.connection

    def get_feedback_connection(self):
        """Feedback connection"""
        if not self.feedback_connection:
            self.feedback_connection = FeedbackConnection(self.cert_file, self.key_file, self.env)
        return self.feedback_connection

    def init_data(self, token=None, payload=None):
        if not token or not payload:
            raise ValueError("need token and payload")

        payload = payload.json()
        token = token.replace(' ', '')
        hex_token = binascii.unhexlify(token)
        fmt = ''.join(NOTIFICATION_STRUCT_FORMAT) % len(payload)
        notification = pack(fmt, 0, 32, hex_token, len(payload), payload)
        return notification

    def send(self, token=None, payload=None):
        notification = self.init_data(token, payload)
        # fallback for send error
        has_try_count = 0
        for i in range(RETRY_COUNT):
            try:
                result = self.get_connection().send(notification)
                return int(result) <= 293 or False
            except Exception as ex:
                logger.error('send failed: %s' % ex)
                has_try_count += 1
                logger.warning("APNS send failed, has tried " + str(has_try_count) + " times.")
        return False

    def send_multi(self, frame):
        self.get_connection().send_multi(frame)

    def feedback(self):
        return self.get_feedback_connection().get_result()


class APNSConnection(object):
    ADDRESSES = {
        "push_sandbox": ("gateway.sandbox.push.apple.com", 2195),
        "push_prod": ("gateway.push.apple.com", 2195),
    }
    FEEDBACK_ADDRESSES = {
        "feedback_sandbox": ("feedback.sandbox.push.apple.com", 2196),
        "feedback_prod": ("feedback.push.apple.com", 2196)
    }

    def __init__(self, cert_file=None, key_file=None, env='push_sandbox',
                 timeout=DEFAULT_CONNECTION_TIMEOUT):
        super(APNSConnection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.env = env
        self.timeout = timeout
        self.ssl_sock = None
        self._socket = None
        self.server_addr = ()       # tuple address

    def _connection(self):
        if not self.server_addr:
            print self.server_addr
            raise ValueError("Unknown address mapping: {0}".format(self.env))

        logger.info('[*]Connecting %s ...' % self.server_addr[0])
        # retry when connection timeout
        for i in range(RETRY_COUNT):
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.timeout)
                self.ssl_sock = ssl.wrap_socket(
                    sock=self._socket,
                    certfile=self.cert_file,
                    keyfile=self.key_file
                )
                self.ssl_sock.connect(self.server_addr)
                logger.info('[√]connection succeed %s ...' % self.server_addr[0])
                break
            except socket.timeout:
                pass
            except:
                raise
        return self.ssl_sock

    @property
    def get_connection(self):
        if not self.ssl_sock:
            self._connection()
        return self.ssl_sock

    def send(self, msg):
        return self.get_connection.write(msg)

    def send_multi(self, frame):
        return self.get_connection.write(str(frame))

    def read(self, n=None):
        return self.get_connection.read(n)

    def __del__(self):
        if self._socket:
            self._socket.close()
        if self.ssl_sock:
            self.ssl_sock.close()
        logger.info("[x]%s APNS connection close " % self.__class__.__name__)


class GatewayConnection(APNSConnection):
    def __init__(self, *args, **kwargs):
        super(GatewayConnection, self).__init__(*args, **kwargs)
        self.server_addr = APNSConnection.ADDRESSES.get(self.env)


class FeedbackConnection(APNSConnection):
    def __init__(self, *args, **kwargs):
        super(FeedbackConnection, self).__init__(*args, **kwargs)
        feed_back_env = self.env.replace('push', 'feedback')
        self.server_addr = APNSConnection.FEEDBACK_ADDRESSES.get(feed_back_env)

    def _get_chunk(self):
        while True:
            result = self.read(BUF_SIZE)
            if not result:
                break
            yield result

    def get_result(self):
        """
        A generator that yields (token_hex, fail_time) pairs
        ref: https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Appendixes/BinaryProviderAPI.html#//apple_ref/doc/uid/TP40008194-CH106-SW5
        """
        buf = ''
        for chunk in self._get_chunk():
            buf += chunk

            # if no more data to read, quit
            # sanity check: after a socket read we should always have at least
            # 6 bytes in the buffer.
            if not chunk or len(chunk) < 6:
                break

            # print chunk

            while len(buf) > 6:
                token_length = unpack('>H', chunk[4:6])[0]
                bytes_to_read = 6 + token_length
                if len(buf) >= bytes_to_read:
                    fail_time_unix = unpack('>I', chunk[0:4])[0]
                    fail_time = datetime.utcfromtimestamp(fail_time_unix)
                    token = binascii.b2a_hex(buf[6: bytes_to_read])
                    yield (token, fail_time)
                    buf = buf[bytes_to_read:]
                else:
                    break

            # fmt = ''.join(FEEDBACK_STRUCT_FORMAT)
            # s = struct.unpack(fmt, chunk)

class Frame(object):
    """
    The Binary Interface and Notification Format
    multiple notifications
    ref: https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Appendixes/BinaryProviderAPI.html#//apple_ref/doc/uid/TP40008194-CH106-SW12
    """
    def __init__(self):
        self.frame_data = bytearray()

    def add_item(self, token_hex, payload, identifier,
                 expiration, priority):
        """add item to frame data"""
        item_len = 0
        self.frame_data.extend('\2' + pack('>I', item_len))

        # Item ID 1, Item Name: Device token
        token_bin = binascii.a2b_hex(token_hex)
        token_length_bin = pack('>H', len(token_bin))
        token_item = '\1' + token_length_bin + token_bin
        self.frame_data.extend(token_item)
        item_len += len(token_item)

        # Item ID 2, Item name: Payload
        payload_json = payload.json()
        payload_length_bin = pack('>H', len(payload_json))
        payload_item = '\2' + payload_length_bin + payload_json
        self.frame_data.extend(payload_item)
        item_len += len(payload_item)

        # Item ID 3, Item name: Notification identifier
        identifier_bin = pack('>I', identifier)
        identifier_length_bin = pack('>H', len(identifier_bin))
        identifier_item = '\3' + identifier_length_bin + identifier_bin
        self.frame_data.extend(identifier_item)
        item_len += len(identifier_item)

        # Item ID 4, Item name: Expiration date
        expiry_bin = pack('>I', expiration)
        expiry_length_bin = pack('>H', len(expiry_bin))
        expiry_item = '\4' + expiry_length_bin + expiry_bin
        self.frame_data.extend(expiry_item)
        item_len += len(expiry_item)

        # Item ID 5, Item name: Priority
        priority_bin = pack('>B', priority)
        priority_length_bin = pack('>H', len(priority_bin))
        priority_item = '\5' + priority_length_bin + priority_bin
        self.frame_data.extend(priority_item)
        item_len += len(priority_item)

        self.frame_data[-item_len-4: -item_len] = pack('>I', item_len)

    def __str__(self):
        return str(self.frame_data)



