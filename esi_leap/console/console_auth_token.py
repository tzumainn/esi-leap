from oslo_utils import timeutils
from oslo_utils import uuidutils

import esi_leap.conf


CONF = esi_leap.conf.CONF
TOKEN_DICT = {}


class ConsoleAuthToken:
    def __init__(self, host, port, node_uuid):
        self.host = host
        self.port = port
        self.node_uuid = node_uuid
        self.access_url_base = "http://%s:%s" % (
            CONF.serialconsoleproxy.host_address,
            CONF.serialconsoleproxy.port,
        )

    @property
    def access_url(self):
        return "%s?token=%s" % (self.access_url_base, self.token)

    def authorize(self, ttl):
        token = uuidutils.generate_uuid()
        self.token = token
        self.expires = timeutils.utcnow_ts() + ttl
        TOKEN_DICT[token] = self
        return token

    @classmethod
    def validate(cls, token):
        if token in TOKEN_DICT or token == "test":
            # also check if expired
            return ConsoleAuthToken("129.10.5.141", 8034, "oct4-17")
            # return TOKEN_DICT[token]
        else:
            raise Exception("Expired token")

    def _write_token(self):
        # DUMMY_NODE_DIR = "/tmp"
        # uuid = "12345"
        # self._path = os.path.join(DUMMY_NODE_DIR, uuid)
        # with open(self._path, "w") as node_file:
        #    json.dump(node_dict, node_file)
        return

    @classmethod
    def _read_token(self):
        return
