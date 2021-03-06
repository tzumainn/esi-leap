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

import datetime
import http.client as http_client
import mock
from oslo_utils import uuidutils
import testtools

from esi_leap.api.controllers.v1.offer import OffersController
from esi_leap.common import exception
from esi_leap.common import statuses
from esi_leap.objects import offer
from esi_leap.resource_objects.ironic_node import IronicNode
from esi_leap.resource_objects.test_node import TestNode
from esi_leap.tests.api import base as test_api_base


def _get_offer_response(o, use_datetime=False):
    if use_datetime:
        start = datetime.datetime(2016, 7, 16)
        end = datetime.datetime(2016, 10, 24)
    else:
        start = '2016-07-16T00:00:00'
        end = '2016-10-24T00:00:00'

    return {
        'resource_type': o.resource_type,
        'resource_uuid': o.resource_uuid,
        'name': o.name,
        'project_id': o.project_id,
        'start_time': start,
        'end_time': end,
        'status': o.status,
        'availabilities': [],
        'uuid': o.uuid,
        'parent_lease_uuid': None
    }


class TestOffersController(test_api_base.APITestCase):

    def setUp(self):
        super(TestOffersController, self).setUp()

        start = datetime.datetime(2016, 7, 16)
        self.test_offer = offer.Offer(
            resource_type='test_node',
            resource_uuid=uuidutils.generate_uuid(),
            name="test_offer",
            uuid=uuidutils.generate_uuid(),
            status=statuses.AVAILABLE,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=self.context.project_id,
            parent_lease_uuid=None
        )
        self.test_offer_drt = offer.Offer(
            resource_type='ironic_node',
            resource_uuid=uuidutils.generate_uuid(),
            name="test_offer",
            uuid=uuidutils.generate_uuid(),
            status=statuses.AVAILABLE,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=self.context.project_id,
            parent_lease_uuid=None
        )
        self.test_offer_lessee = offer.Offer(
            resource_type='test_node',
            resource_uuid=uuidutils.generate_uuid(),
            name="test_offer",
            uuid=uuidutils.generate_uuid(),
            lessee_id='lessee-uuid',
            status=statuses.AVAILABLE,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=self.context.project_id,
            parent_lease_uuid=None
        )
        self.test_offer_2 = offer.Offer(
            resource_type='test_node',
            resource_uuid=uuidutils.generate_uuid(),
            name="test_offer2",
            uuid=uuidutils.generate_uuid(),
            status=statuses.DELETED,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=self.context.project_id,
            parent_lease_uuid=None
        )
        self.test_offer_with_parent = offer.Offer(
            resource_type='test_node',
            resource_uuid=uuidutils.generate_uuid(),
            name="test_offer",
            uuid=uuidutils.generate_uuid(),
            status=statuses.AVAILABLE,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=self.context.project_id,
            parent_lease_uuid='parent-lease-uuid'
        )

    def test_empty(self):
        data = self.get_json('/offers')
        self.assertEqual([], data['offers'])

    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_resource_admin')
    @mock.patch('esi_leap.objects.offer.Offer.create')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    def test_post(self, mock_aoa, mock_create, mock_cra, mock_generate_uuid,
                  mock_gro):
        resource = TestNode(self.test_offer.resource_uuid)
        mock_gro.return_value = resource
        mock_generate_uuid.return_value = self.test_offer.uuid
        mock_create.return_value = self.test_offer
        mock_aoa.return_value = self.test_offer.to_dict()

        data = {
            "resource_type": self.test_offer.resource_type,
            "resource_uuid": self.test_offer.resource_uuid,
            "name": self.test_offer.name,
            "start_time": "2016-07-16T00:00:00",
            "end_time": "2016-10-24T00:00:00"
        }

        request = self.post_json('/offers', data)

        data['project_id'] = self.context.project_id
        data['uuid'] = self.test_offer.uuid
        data['status'] = statuses.AVAILABLE
        data['parent_lease_uuid'] = None

        mock_gro.assert_called_once_with(self.test_offer.resource_type,
                                         self.test_offer.resource_uuid)
        mock_cra.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_create.assert_called_once()
        mock_aoa.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)

    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_resource_admin')
    @mock.patch('esi_leap.objects.offer.Offer.create')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    def test_post_default_resource_type(self, mock_aoa, mock_create, mock_cra,
                                        mock_generate_uuid, mock_gro):
        resource = IronicNode(self.test_offer_drt.resource_uuid)
        mock_gro.return_value = resource
        mock_generate_uuid.return_value = self.test_offer_drt.uuid
        mock_aoa.return_value = self.test_offer_drt.to_dict()

        data = {
            "resource_uuid": self.test_offer_drt.resource_uuid,
            "name": self.test_offer_drt.name,
            "start_time": "2016-07-16T00:00:00",
            "end_time": "2016-10-24T00:00:00"
        }

        request = self.post_json('/offers', data)

        data['project_id'] = self.context.project_id
        data['uuid'] = self.test_offer_drt.uuid
        data['status'] = statuses.AVAILABLE
        data['resource_type'] = 'ironic_node'
        data['parent_lease_uuid'] = None

        mock_gro.assert_called_once_with(self.test_offer_drt.resource_type,
                                         self.test_offer_drt.resource_uuid)
        mock_cra.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_create.assert_called_once()
        mock_aoa.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)

    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('esi_leap.common.keystone.get_project_uuid_from_ident')
    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_resource_admin')
    @mock.patch('esi_leap.objects.offer.Offer.create')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    def test_post_lessee(self, mock_aoa, mock_create, mock_cra,
                         mock_generate_uuid, mock_gpufi, mock_gro):
        resource = TestNode(self.test_offer_lessee.resource_uuid)
        mock_gro.return_value = resource
        mock_gpufi.return_value = 'lessee_uuid'
        mock_generate_uuid.return_value = self.test_offer_lessee.uuid
        mock_create.return_value = self.test_offer_lessee
        mock_aoa.return_value = self.test_offer_lessee.to_dict()

        data = {
            "resource_type": self.test_offer_lessee.resource_type,
            "resource_uuid": self.test_offer_lessee.resource_uuid,
            "name": self.test_offer_lessee.name,
            "start_time": "2016-07-16T00:00:00",
            "end_time": "2016-10-24T00:00:00",
            "lessee_id": "lessee-uuid"
        }

        request = self.post_json('/offers', data)

        data['project_id'] = self.context.project_id
        data['uuid'] = self.test_offer_lessee.uuid
        data['status'] = statuses.AVAILABLE
        data['parent_lease_uuid'] = None

        mock_gro.assert_called_once_with(self.test_offer_lessee.resource_type,
                                         self.test_offer_lessee.resource_uuid)
        mock_gpufi.assert_called_once_with('lessee-uuid')
        mock_cra.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_create.assert_called_once()
        mock_aoa.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)

    @mock.patch('esi_leap.api.controllers.v1.utils.'
                'check_resource_lease_admin')
    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_resource_admin')
    @mock.patch('esi_leap.objects.offer.Offer.create')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    def test_post_non_admin_parent_lease(self, mock_aoa, mock_create,
                                         mock_cra, mock_generate_uuid,
                                         mock_gro, mock_crla):
        resource = TestNode(self.test_offer_with_parent.resource_uuid)
        mock_gro.return_value = resource
        mock_generate_uuid.return_value = self.test_offer_with_parent.uuid
        mock_create.return_value = self.test_offer_with_parent
        mock_aoa.return_value = self.test_offer_with_parent.to_dict()
        mock_cra.side_effect = exception.HTTPResourceForbidden(
            resource_type='test_node',
            resource=self.test_offer_with_parent.resource_uuid)
        mock_crla.return_value = self.test_offer_with_parent.parent_lease_uuid

        data = {
            "resource_type": self.test_offer_with_parent.resource_type,
            "resource_uuid": self.test_offer_with_parent.resource_uuid,
            "name": self.test_offer_with_parent.name,
            "start_time": "2016-07-16T00:00:00",
            "end_time": "2016-10-24T00:00:00"
        }

        request = self.post_json('/offers', data)

        data['project_id'] = self.context.project_id
        data['uuid'] = self.test_offer_with_parent.uuid
        data['status'] = statuses.AVAILABLE
        data['parent_lease_uuid'] = \
            self.test_offer_with_parent.parent_lease_uuid

        mock_gro.assert_called_once_with(
            self.test_offer_with_parent.resource_type,
            self.test_offer_with_parent.resource_uuid)
        mock_cra.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_crla.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_create.assert_called_once()
        mock_aoa.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)

    @mock.patch('esi_leap.api.controllers.v1.utils.'
                'check_resource_lease_admin')
    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_resource_admin')
    @mock.patch('esi_leap.objects.offer.Offer.create')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    def test_post_non_admin_no_parent_lease(self, mock_aoa, mock_create,
                                            mock_cra, mock_generate_uuid,
                                            mock_gro, mock_crla):
        resource = TestNode(self.test_offer_with_parent.resource_uuid)
        mock_gro.return_value = resource
        mock_generate_uuid.return_value = self.test_offer_with_parent.uuid
        mock_create.return_value = self.test_offer_with_parent
        mock_aoa.return_value = self.test_offer_with_parent.to_dict()
        mock_cra.side_effect = exception.HTTPResourceForbidden(
            resource_type='test_node',
            resource=self.test_offer_with_parent.resource_uuid)
        mock_crla.return_value = None

        data = {
            "resource_type": self.test_offer_with_parent.resource_type,
            "resource_uuid": self.test_offer_with_parent.resource_uuid,
            "name": self.test_offer_with_parent.name,
            "start_time": "2016-07-16T00:00:00",
            "end_time": "2016-10-24T00:00:00"
        }

        request = self.post_json('/offers', data, expect_errors=True)

        mock_gro.assert_called_once_with(
            self.test_offer_with_parent.resource_type,
            self.test_offer_with_parent.resource_uuid)
        mock_cra.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_crla.assert_called_once_with(
            self.context.to_policy_values(),
            resource,
            self.context.project_id,
            datetime.datetime(2016, 7, 16, 0, 0, 0),
            datetime.datetime(2016, 10, 24, 0, 0, 0))
        mock_create.assert_not_called()
        mock_aoa.assert_not_called()
        self.assertEqual(http_client.FORBIDDEN, request.status_int)

    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test_get_nofilters(self, mock_get_all, mock_aoaan):
        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]

        expected_filters = {'status': 'available'}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json('/offers')

        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test_get_any_status(self, mock_get_all, mock_aoaan):
        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]

        expected_filters = {}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json('/offers/?status=any')

        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.common.keystone.get_project_uuid_from_ident')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test_get_project_filter(self, mock_get_all, mock_aoaan,
                                mock_gpufi):

        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]
        mock_gpufi.return_value = self.context.project_id

        expected_filters = {'project_id': self.context.project_id,
                            'status': 'available'}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json(
            '/offers/?project_id=' + self.context.project_id)

        mock_gpufi.assert_called_once_with(self.context.project_id)
        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test_get_resource_filter(self, mock_get_all, mock_aoaan, mock_gro):
        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]
        mock_gro.return_value = TestNode('54321')

        expected_filters = {'status': 'available',
                            'resource_uuid': '54321',
                            'resource_type': 'test_node'}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json(
            '/offers/?resource_uuid=54321&resource_type=test_node')

        mock_gro.assert_called_once_with('test_node', '54321')
        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.resource_objects.resource_object_factory.'
                'ResourceObjectFactory.get_resource_object')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test_get_resource_filter_default_resource_type(self, mock_get_all,
                                                       mock_aoaan,
                                                       mock_gro):
        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]
        mock_gro.return_value = IronicNode('54321')

        expected_filters = {'status': 'available',
                            'resource_uuid': '54321',
                            'resource_type': 'ironic_node'}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json(
            '/offers/?resource_uuid=54321')

        mock_gro.assert_called_once_with('ironic_node', '54321')
        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    @mock.patch('esi_leap.api.controllers.v1.utils.policy_authorize')
    def test_get_lessee_filter(self, mock_authorize, mock_get_all,
                               mock_aoaan):
        mock_get_all.return_value = [self.test_offer, self.test_offer_2]
        mock_aoaan.side_effect = [
            _get_offer_response(self.test_offer, use_datetime=True),
            _get_offer_response(self.test_offer_2, use_datetime=True)]
        mock_authorize.side_effect = [
            None,
            exception.HTTPForbidden(rule='esi_leap:offer:get')
        ]

        expected_filters = {'status': 'available',
                            'lessee_id': self.context.project_id}
        expected_resp = {'offers': [_get_offer_response(self.test_offer),
                                    _get_offer_response(self.test_offer_2)]}

        request = self.get_json('/offers')

        mock_get_all.assert_called_once_with(expected_filters, self.context)
        assert mock_aoaan.call_count == 2
        self.assertEqual(request, expected_resp)

    @mock.patch('esi_leap.api.controllers.v1.utils.check_offer_lessee')
    @mock.patch('esi_leap.api.controllers.v1.utils.get_offer')
    @mock.patch('esi_leap.api.controllers.v1.offer.' +
                'OffersController._add_offer_availabilities_and_names')
    @mock.patch('esi_leap.api.controllers.v1.utils.policy_authorize')
    def test_get_one(self, mock_authorize, mock_aoa, mock_get_offer,
                     mock_col):
        mock_get_offer.return_value = self.test_offer
        mock_aoa.return_value = self.test_offer.to_dict()

        self.get_json('/offers/' + self.test_offer.uuid)

        mock_authorize.assert_called_once_with('esi_leap:offer:get',
                                               self.context.to_policy_values())
        mock_get_offer.assert_called_once_with(self.test_offer.uuid)
        mock_col.assert_called_once_with(self.context.to_policy_values(),
                                         self.test_offer)
        mock_aoa.assert_called_once_with(self.test_offer)

    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.objects.lease.Lease.create')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_offer_lessee')
    @mock.patch('esi_leap.api.controllers.v1.utils.get_offer')
    def test_claim(self, mock_get_offer, mock_col, mock_lease_create,
                   mock_generate_uuid):
        lease_uuid = '12345'
        mock_generate_uuid.return_value = lease_uuid
        mock_get_offer.return_value = self.test_offer
        data = {
            "name": "lease_claim",
            "start_time": "2016-07-16T19:20:30",
            "end_time": "2016-08-16T19:20:30"
        }

        request = self.post_json('/offers/' + self.test_offer.uuid + '/claim',
                                 data)

        data['project_id'] = self.context.project_id
        data['uuid'] = lease_uuid
        data['offer_uuid'] = self.test_offer.uuid
        data['resource_type'] = self.test_offer.resource_type
        data['resource_uuid'] = self.test_offer.resource_uuid
        data['owner_id'] = self.test_offer.project_id

        mock_get_offer.assert_called_once_with(self.test_offer.uuid,
                                               statuses.AVAILABLE)
        mock_col.assert_called_once_with(self.context.to_policy_values(),
                                         self.test_offer)
        mock_lease_create.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)

    @mock.patch('oslo_utils.uuidutils.generate_uuid')
    @mock.patch('esi_leap.objects.lease.Lease.create')
    @mock.patch('esi_leap.api.controllers.v1.utils.check_offer_lessee')
    @mock.patch('esi_leap.api.controllers.v1.utils.get_offer')
    def test_claim_parent_lease(self, mock_get_offer, mock_col,
                                mock_lease_create, mock_generate_uuid):
        lease_uuid = '12345'
        mock_generate_uuid.return_value = lease_uuid
        mock_get_offer.return_value = self.test_offer_with_parent
        data = {
            "name": "lease_claim",
            "start_time": "2016-07-16T19:20:30",
            "end_time": "2016-08-16T19:20:30"
        }

        request = self.post_json(
            '/offers/' + self.test_offer_with_parent.uuid + '/claim',
            data)

        data['project_id'] = self.context.project_id
        data['uuid'] = lease_uuid
        data['offer_uuid'] = self.test_offer_with_parent.uuid
        data['resource_type'] = self.test_offer_with_parent.resource_type
        data['resource_uuid'] = self.test_offer_with_parent.resource_uuid
        data['owner_id'] = self.test_offer_with_parent.project_id
        data['parent_lease_uuid'] = \
            self.test_offer_with_parent.parent_lease_uuid

        mock_get_offer.assert_called_once_with(
            self.test_offer_with_parent.uuid, statuses.AVAILABLE)
        mock_col.assert_called_once_with(self.context.to_policy_values(),
                                         self.test_offer_with_parent)
        mock_lease_create.assert_called_once()
        self.assertEqual(data, request.json)
        self.assertEqual(http_client.CREATED, request.status_int)


class TestOffersControllerStaticMethods(testtools.TestCase):

    @mock.patch('esi_leap.common.keystone.get_project_name')
    @mock.patch('esi_leap.objects.offer.Offer.get_availabilities')
    def test__add_offer_availabilities_and_names(self,
                                                 mock_get_availabilities,
                                                 mock_gpn):
        mock_get_availabilities.return_value = []
        mock_gpn.return_value = 'project-name'

        start = datetime.datetime(2016, 7, 16)
        o = offer.Offer(
            resource_type='test_node',
            resource_uuid='1234567890',
            name="o",
            status=statuses.AVAILABLE,
            start_time=start,
            end_time=start + datetime.timedelta(days=100),
            project_id=uuidutils.generate_uuid(),
            lessee_id=None
        )

        o_dict = OffersController._add_offer_availabilities_and_names(o)

        expected_offer_dict = {
            'resource_type': o.resource_type,
            'resource_uuid': o.resource_uuid,
            'resource': 'test-node-1234567890',
            'name': o.name,
            'project_id': o.project_id,
            'project': 'project-name',
            'lessee_id': None,
            'lessee': 'project-name',
            'start_time': o.start_time,
            'end_time': o.end_time,
            'status': o.status,
            'availabilities': [],
        }

        self.assertEqual(expected_offer_dict, o_dict)
        self.assertEqual(2, mock_gpn.call_count)
