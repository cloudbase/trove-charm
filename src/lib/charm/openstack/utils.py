# Copyright 2023 Cloudbase Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools

from charmhelpers.core import hookenv
from keystoneauth1 import identity as ks_identity
from keystoneauth1 import session as ks_session
from neutronclient.v2_0 import client as neutron_client

from charm.openstack import exceptions


SYSTEM_CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'
TROVE_MGMT_SG = 'trove-sec-group'
TROVE_TAG = 'charm-trove'


def api_exc_wrapper(exc_list, service, resource_type):
    def decorator(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exc_list as exc:
                raise exceptions.APIException(
                    service=service, resource_type=resource_type, exc=exc)
        return inner
    return decorator


def endpoint_type():
    if hookenv.config('use-internal-endpoints'):
        return 'internalURL'
    return 'publicURL'


def get_session_from_keystone(keystone):
    protocol = keystone.auth_protocol()
    host = keystone.auth_host()
    port = keystone.auth_port()
    auth_url = f"{protocol}://{host}:{port}/"
    auth = ks_identity.Password(
        auth_url=auth_url,
        username=keystone.service_username(),
        password=keystone.service_password(),
        project_name=keystone.service_tenant(),
        user_domain_name=keystone.service_domain(),
        project_domain_name=keystone.service_domain(),
    )
    return ks_session.Session(auth=auth, verify=SYSTEM_CA_BUNDLE)


def get_neutron_client(session):
    return neutron_client.Client(
        session=session, region_name=hookenv.config('region'),
        endpoint_type=endpoint_type(),
    )


def get_trove_mgmt_sec_group(keystone):
    """Returns the ID of the Trove Management Network Security Group.

    Returns the Security Group ID tagged with `charm-trove`. If it doesn't
    exist, it will be created.
    """
    session = get_session_from_keystone(keystone)
    client = get_neutron_client(session)

    sec_group = _get_or_create_sec_group(client)
    return sec_group['id']


def update_trove_mgmt_sec_group(keystone, rabbitmq_ips, rabbitmq_port):
    """Updates Trove Management Network Security Group and returns its ID.

    Creates the Trove Management Network Security Group if it doesn't exist,
    removing its default egress rules, and updates the Security Group to
    contain egress rules for the given RabbitMQ IPs.
    """
    session = get_session_from_keystone(keystone)
    client = get_neutron_client(session)

    sec_group = _get_or_create_sec_group(client)
    egress_rules = [rule for rule in sec_group['security_group_rules'] if
                    rule['direction'] == 'egress' and
                    rule['ethertype'] == 'IPv4' and
                    rule['protocol'] == 'tcp']

    # Get the IPs for which we should add egress rules for.
    ips_to_add = []
    for ip in rabbitmq_ips:
        found = False
        for rule in egress_rules:
            if (rule['remote_ip_prefix'] == ip and
                    rule['port_range_min'] == rabbitmq_port):
                found = True
                break

        if not found:
            ips_to_add.append(ip)

    for ip in ips_to_add:
        _create_sec_group_rule(client, sec_group['id'], 'egress', 'tcp',
                               ip, rabbitmq_port)

    # Delete egress rules that do not apply for the current IPs.
    rules_to_delete = [rule for rule in egress_rules if
                       rule['port_range_min'] != rabbitmq_port or
                       rule['remote_ip_prefix'] not in rabbitmq_ips]
    for rule in rules_to_delete:
        client.delete_security_group_rule(rule['id'])

    return sec_group['id']


@api_exc_wrapper(exceptions.NEUTRON_EXCS, 'neutron', 'security_group')
def _get_or_create_sec_group(client):
    resp = client.list_security_groups(tags=TROVE_TAG)
    sec_groups = resp.get('security_groups', [])
    if len(sec_groups) > 1:
        raise exceptions.DuplicateResource('security-group', sec_groups)

    if sec_groups:
        return sec_groups[0]

    # Create the security group only if it doesn't exist.
    sec_group = _create_sec_group(client)

    # Delete the default rules.
    for rule in sec_group['security_group_rules']:
        client.delete_security_group_rule(rule['id'])

    # We removed the rules.
    sec_group['security_group_rules'] = []

    return sec_group


def _create_sec_group(client):
    params = {
        'name': TROVE_MGMT_SG,
        'description': 'Trove management network security group',
    }
    resp = client.create_security_group({'security_group': params})
    sec_group = resp['security_group']

    # We cannot add tags during creation.
    client.add_tag('security-groups', sec_group['id'], TROVE_TAG)

    return sec_group


@api_exc_wrapper(exceptions.NEUTRON_EXCS, 'neutron', 'security_group_rule')
def _create_sec_group_rule(client, sec_group_id, direction, protocol=None,
                           remote_ip=None, port_min=None, port_max=None):
    port_max = port_max or port_min

    params = {
        'security_group_id': sec_group_id,
        'direction': direction,
        'protocol': protocol,
        'ethertype': 'IPv4',
        'remote_ip_prefix': remote_ip,
        'port_range_min': port_min,
        'port_range_max': port_max,
    }

    client.create_security_group_rule({'security_group_rule': params})
