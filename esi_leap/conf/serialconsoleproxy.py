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

from oslo_config import cfg


opts = [
    cfg.HostAddressOpt("host_address", default="0.0.0.0"),
    cfg.PortOpt("port", default=6083),
    cfg.IntOpt("timeout", default=-1),
    cfg.IntOpt("token_ttl", default=600),
]


serialconsoleproxy_group = cfg.OptGroup(
    "serialconsoleproxy", title="Serial Console Proxy Options"
)


def register_opts(conf):
    conf.register_opts(opts, group=serialconsoleproxy_group)
