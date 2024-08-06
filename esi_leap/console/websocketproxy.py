#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Websocket proxy adapted from similar code in Nova
"""

from http import HTTPStatus
import os
import socket
import threading
import traceback
from urllib import parse as urlparse
import websockify

from oslo_utils import importutils
from oslo_utils import timeutils

from esi_leap.common import ironic
import esi_leap.conf
from esi_leap.objects import console_auth_token


CONF = esi_leap.conf.CONF


# Location of WebSockifyServer class in websockify v0.9.0
websockifyserver = importutils.try_import("websockify.websockifyserver")


class ProxyRequestHandler(websockify.ProxyRequestHandler):
    def __init__(self, *args, **kwargs):
        websockify.ProxyRequestHandler.__init__(self, *args, **kwargs)

    def verify_origin_proto(self, connect_info, origin_proto):
        if "access_url_base" not in connect_info:
            detail = "No access_url_base in connect_info."
            raise Exception(detail)
            # raise exception.ValidationError(detail=detail)

        expected_protos = [urlparse.urlparse(connect_info.access_url_base).scheme]
        # NOTE: For serial consoles the expected protocol could be ws or
        # wss which correspond to http and https respectively in terms of
        # security.
        if "ws" in expected_protos:
            expected_protos.append("http")
        if "wss" in expected_protos:
            expected_protos.append("https")

        return origin_proto in expected_protos

    def _get_connect_info(self, token):
        """Validate the token and get the connect info."""
        connect_info = console_auth_token.ConsoleAuthToken.validate(token)
        if CONF.serialconsoleproxy.timeout > 0:
            connect_info.expires = (
                timeutils.utcnow_ts() + CONF.serialconsoleproxy.timeout
            )

        # get host and port
        console_info = ironic.get_ironic_client().node.get_console(connect_info[node_uuid])
        url = urlparse.urlparse(console_info["console_info"]["url"])
        connect_info[host] = url.hostname
        connect_info[port] = url.port

        return connect_info

    def _close_connection(self, tsock, host, port):
        """takes target socket and close the connection."""
        try:
            tsock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            if tsock.fileno() != -1:
                tsock.close()
                print(
                    "%(host)s:%(port)s: "
                    "Websocket client or target closed" % {"host": host, "port": port}
                )

    def new_websocket_client(self):
        """Called after a new WebSocket connection has been established."""
        # Reopen the eventlet hub to make sure we don't share an epoll
        # fd with parent and/or siblings, which would be bad
        from eventlet import hubs

        hubs.use_hub()

        token = (
            urlparse.parse_qs(urlparse.urlparse(self.path).query)
            .get("token", [""])
            .pop()
        )

        try:
            connect_info = self._get_connect_info(token)
        except Exception:
            print(traceback.format_exc())
            raise

        host = connect_info.host
        port = connect_info.port

        # Connect to the target
        print("connecting to: %(host)s:%(port)s" % {"host": host, "port": port})
        tsock = self.socket(host, port, connect=True)

        # Start proxying
        try:
            if CONF.serialconsoleproxy.timeout > 0:
                conn_timeout = connect_info.expires - timeutils.utcnow_ts()
                print("%s seconds to terminate connection." % conn_timeout)
                threading.Timer(
                    conn_timeout, self._close_connection, [tsock, host, port]
                ).start()
            self.do_proxy(tsock)
        except Exception:
            print(traceback.format_exc())
            raise
        finally:
            self._close_connection(tsock, host, port)

    def socket(self, *args, **kwargs):
        return websockifyserver.WebSockifyServer.socket(*args, **kwargs)

    def send_head(self):
        # This code is copied from this example patch:
        # https://bugs.python.org/issue32084#msg306545
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            parts = urlparse.urlsplit(self.path)
            if not parts.path.endswith("/"):
                # Browsers interpret "Location: //uri" as an absolute URI
                # like "http://URI"
                if self.path.startswith("//"):
                    self.send_error(
                        HTTPStatus.BAD_REQUEST, "URI must not start with //"
                    )
                    return None

        return super(ProxyRequestHandler, self).send_head()


class WebSocketProxy(websockify.WebSocketProxy):
    def __init__(self, *args, **kwargs):
        super(WebSocketProxy, self).__init__(*args, **kwargs)
