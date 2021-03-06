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

import itertools

from oslo_policy import policy

import esi_leap.conf

CONF = esi_leap.conf.CONF
_ENFORCER = None

default_policies = [
    policy.RuleDefault('is_admin',
                       'role:admin or role:esi_leap_admin',
                       description='Full read/write API access'),
    policy.RuleDefault('is_owner',
                       'role:owner or role:esi_leap_owner',
                       description='Owner API access'),
    policy.RuleDefault('is_lessee',
                       'role:lessee or role:esi_leap_lessee',
                       description='Lessee API access'),
]

lease_policies = [
    policy.DocumentedRuleDefault(
        'esi_leap:lease:lease_admin',
        'rule:is_admin',
        'Complete permissions over leases',
        [{'path': '/leases', 'method': 'POST'},
         {'path': '/leases', 'method': 'GET'},
         {'path': '/leases/{lease_ident}', 'method': 'GET'},
         {'path': '/leases/{lease_ident}', 'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:lease:create',
        'rule:is_admin or rule:is_owner',
        'Create lease',
        [{'path': '/leases', 'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:lease:get',
        'rule:is_admin or rule:is_lessee or rule:is_owner',
        'Retrieve all leases owned by project_id',
        [{'path': '/leases', 'method': 'GET'},
         {'path': '/leases/{lease_ident}', 'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:lease:delete',
        'rule:is_admin or rule:is_owner or rule:is_lessee',
        'Delete lease',
        [{'path': '/leases/{lease_ident}', 'method': 'DELETE'}]),
]

offer_policies = [
    policy.DocumentedRuleDefault(
        'esi_leap:offer:offer_admin',
        'rule:is_admin',
        'Complete permissions over offers',
        [{'path': '/offers', 'method': 'POST'},
         {'path': '/offers', 'method': 'GET'},
         {'path': '/offers/{offer_ident}', 'method': 'GET'},
         {'path': '/offers/{offer_ident}', 'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:offer:create',
        'rule:is_admin or rule:is_owner',
        'Create offer',
        [{'path': '/offers', 'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:offer:get',
        'rule:is_admin or rule:is_owner or rule:is_lessee',
        'Retrieve offer',
        [{'path': '/offers', 'method': 'GET'},
         {'path': '/offers/{offer_ident}', 'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:offer:delete',
        'rule:is_admin or rule:is_owner',
        'Delete offer',
        [{'path': '/offers/{offer_ident}', 'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:offer:claim',
        'rule:is_admin or rule:is_lessee',
        'Claim an offer',
        [{'path': '/offers/{offer_ident}/claim', 'method': 'POST'}]),
]

owner_change_policies = [
    policy.DocumentedRuleDefault(
        'esi_leap:owner_change:owner_change_admin',
        'rule:is_admin',
        'Complete permissions over owner changes',
        [{'path': '/owner_changes', 'method': 'POST'},
         {'path': '/owner_changes', 'method': 'GET'},
         {'path': '/owner_changes/{owner_change_ident}', 'method': 'GET'},
         {'path': '/owner_changes/{owner_change_ident}', 'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:owner_change:create',
        'rule:is_admin',
        'Create owner change',
        [{'path': '/owner_changes', 'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:owner_change:get',
        'rule:is_admin or rule:is_owner',
        'Retrieve owner change',
        [{'path': '/owner_changes', 'method': 'GET'},
         {'path': '/owner_changes/{owner_change_ident}', 'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        'esi_leap:owner_change:delete',
        'rule:is_admin',
        'Delete owner change',
        [{'path': '/owner_changes/{owner_change_ident}', 'method': 'DELETE'}]),
]


def list_rules():
    policies = itertools.chain(
        default_policies,
        lease_policies,
        offer_policies,
        owner_change_policies,
    )
    return policies


def get_enforcer():
    CONF([], project='esi-leap')
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(CONF)
        _ENFORCER.register_defaults(list_rules())
    return _ENFORCER


def authorize(rule, target, creds, *args, **kwargs):
    if not CONF.pecan.auth_enable:
        return True

    return get_enforcer().authorize(
        rule, target, creds, do_raise=True, *args, **kwargs)
