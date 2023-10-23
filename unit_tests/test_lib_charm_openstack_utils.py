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

import unittest
from unittest import mock

from charmhelpers.core import hookenv

from charm.openstack import exceptions
from charm.openstack import utils


class TestUtils(unittest.TestCase):

    @mock.patch.object(hookenv, 'config')
    def test_endpoint_type(self, mock_config):
        mock_config.return_value = False
        self.assertEquals('publicURL', utils.endpoint_type())

        mock_config.return_value = True
        self.assertEquals('internalURL', utils.endpoint_type())

    @mock.patch.object(utils, 'ks_session')
    @mock.patch.object(utils, 'ks_identity')
    def test_get_session_from_keystone(self, mock_identity, mock_session):
        mock_ks = mock.Mock()

        result = utils.get_session_from_keystone(mock_ks)

        self.assertEqual(mock_session.Session.return_value, result)
        expected_auth_url = "%s://%s:%s/" % (
            mock_ks.auth_protocol.return_value,
            mock_ks.auth_host.return_value,
            mock_ks.auth_port.return_value,
        )
        mock_identity.Password.assert_called_once_with(
            auth_url=expected_auth_url,
            user_domain_name=mock_ks.service_domain.return_value,
            username=mock_ks.service_username.return_value,
            password=mock_ks.service_password.return_value,
            project_domain_name=mock_ks.service_domain.return_value,
            project_name=mock_ks.service_tenant.return_value,
        )
        mock_session.Session.assert_called_once_with(
            auth=mock_identity.Password.return_value,
            verify=utils.SYSTEM_CA_BUNDLE,
        )

    @mock.patch.object(utils, 'endpoint_type')
    @mock.patch.object(hookenv, 'config')
    @mock.patch.object(utils, 'neutron_client')
    def test_get_neutron_client(self, mock_nc, mock_config, mock_endpoint):
        client = utils.get_neutron_client(mock.sentinel.session)

        self.assertEqual(mock_nc.Client.return_value, client)
        mock_config.assert_called_once_with('region')
        mock_nc.Client.assert_called_once_with(
            session=mock.sentinel.session,
            region_name=mock_config.return_value,
            endpoint_type=mock_endpoint.return_value,
        )

    @mock.patch.object(utils, '_get_or_create_sec_group')
    @mock.patch.object(utils, 'get_neutron_client')
    @mock.patch.object(utils, 'get_session_from_keystone')
    def test_get_trove_mgmt_sec_group(
            self, mock_get_sess, mock_get_nc, mock_get_sg):
        mock_get_sg.return_value = {'id': mock.sentinel.group_id}

        sec_group_id = utils.get_trove_mgmt_sec_group(mock.sentinel.keystone)

        self.assertEqual(mock.sentinel.group_id, sec_group_id)
        mock_get_sess.assert_called_once_with(mock.sentinel.keystone)
        mock_client = mock_get_nc.return_value
        mock_get_nc.assert_called_once_with(mock_get_sess.return_value)
        mock_get_sg.assert_called_once_with(mock_client)

    @mock.patch.object(utils, '_create_sec_group_rule')
    @mock.patch.object(utils, '_get_or_create_sec_group')
    @mock.patch.object(utils, 'get_neutron_client')
    @mock.patch.object(utils, 'get_session_from_keystone')
    def test_update_trove_mgmt_sec_group(
            self, mock_get_sess, mock_get_nc, mock_get_sg,
            mock_create_sg_rule):
        # The tested function should:
        # - remove a rule that is no longer needed.
        # - remove a rule with a different port and add a new one.
        # - add a new rule for the new IP.
        # - leave the rest of the rules untouched.
        old_sec_group_rules = [
            {
                'id': mock.sentinel.id1,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip1,
                'port_range_min': mock.sentinel.port,
            },
            {
                'id': mock.sentinel.id2,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip2,
                'port_range_min': mock.sentinel.otherport,
            },
            {
                'id': mock.sentinel.id3,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip3,
                'port_range_min': mock.sentinel.port,
            },
            {
                'id': mock.sentinel.id4,
                'direction': 'ingress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip4,
            },
            {
                'id': mock.sentinel.id5,
                'direction': 'egress',
                'ethertype': 'IPv6',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip5,
            },
            {
                'id': mock.sentinel.id6,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'udp',
                'remote_ip_prefix': mock.sentinel.ip6,
            },
        ]
        mock_get_sg.return_value = {
            'id': mock.sentinel.group_id,
            'security_group_rules': old_sec_group_rules,
        }
        new_rabbitmq_ips = [mock.sentinel.ip2, mock.sentinel.ip3,
                            mock.sentinel.ipnew]

        sec_group_id = utils.update_trove_mgmt_sec_group(
            mock.sentinel.keystone,
            new_rabbitmq_ips,
            mock.sentinel.port,
        )

        self.assertEqual(mock.sentinel.group_id, sec_group_id)
        mock_get_sess.assert_called_once_with(mock.sentinel.keystone)
        mock_client = mock_get_nc.return_value
        mock_get_nc.assert_called_once_with(mock_get_sess.return_value)
        mock_get_sg.assert_called_once_with(mock_client)
        mock_create_sg_rule.assert_has_calls([
            mock.call(mock_client, mock.sentinel.group_id, 'egress', 'tcp',
                      mock.sentinel.ip2, mock.sentinel.port),
            mock.call(mock_client, mock.sentinel.group_id, 'egress', 'tcp',
                      mock.sentinel.ipnew, mock.sentinel.port),
        ])
        mock_client.delete_security_group_rule.assert_has_calls([
            mock.call(mock.sentinel.id1),
            mock.call(mock.sentinel.id2),
        ])

    def test_get_or_create_sec_group_exc(self):
        mock_client = mock.Mock()
        mock_client.list_security_groups.return_value = {
            'security_groups': [mock.sentinel.sec_group] * 2,
        }

        self.assertRaises(
            exceptions.DuplicateResource,
            utils._get_or_create_sec_group,
            mock_client,
        )
        mock_client.list_security_groups.assert_called_once_with(
            tags=utils.TROVE_TAG)

    @mock.patch.object(utils, '_create_sec_group')
    def test_get_or_create_sec_group(self, mock_create_sec_group):
        mock_client = mock.Mock()
        mock_client.list_security_groups.return_value = {
            'security_groups': [mock.sentinel.group],
        }

        sec_group = utils._get_or_create_sec_group(mock_client)

        self.assertEqual(mock.sentinel.group, sec_group)

        mock_client.list_security_groups.return_value = {
            'security_groups': [],
        }
        fake_sec_group_rule = {'id': mock.sentinel.rule_id}
        fake_sec_group = {
            'security_group_rules': [fake_sec_group_rule] * 2,
        }
        mock_create_sec_group.return_value = fake_sec_group

        sec_group = utils._get_or_create_sec_group(mock_client)

        self.assertEqual(fake_sec_group, sec_group)
        self.assertListEqual([], fake_sec_group['security_group_rules'])
        mock_client.delete_security_group_rule.assert_has_calls(
            [mock.call(mock.sentinel.rule_id)] * 2)
        mock_create_sec_group.assert_called_once_with(mock_client)

    def test_create_sec_group(self):
        mock_client = mock.Mock()
        fake_sec_group = {'id': mock.sentinel.sec_group_id}
        mock_client.create_security_group.return_value = {
            'security_group': fake_sec_group}

        sec_group = utils._create_sec_group(mock_client)

        self.assertEqual(fake_sec_group, sec_group)
        expected_params = {
            'name': utils.TROVE_MGMT_SG,
            'description': 'Trove management network security group',
        }
        mock_client.create_security_group.assert_called_once_with(
            {'security_group': expected_params})
        mock_client.add_tag.assert_called_once_with(
            'security-groups', mock.sentinel.sec_group_id, utils.TROVE_TAG)

    def test_create_sec_group_rule(self):
        mock_client = mock.Mock()

        utils._create_sec_group_rule(
            mock_client,
            mock.sentinel.sec_group_id,
            mock.sentinel.direction,
            mock.sentinel.protocol,
            mock.sentinel.remote_ip,
            mock.sentinel.port_min,
        )

        expected_params = {
            'security_group_id': mock.sentinel.sec_group_id,
            'direction': mock.sentinel.direction,
            'protocol': mock.sentinel.protocol,
            'ethertype': 'IPv4',
            'remote_ip_prefix': mock.sentinel.remote_ip,
            'port_range_min': mock.sentinel.port_min,
            'port_range_max': mock.sentinel.port_min,
        }
        mock_client.create_security_group_rule.assert_called_once_with(
            {'security_group_rule': expected_params})
