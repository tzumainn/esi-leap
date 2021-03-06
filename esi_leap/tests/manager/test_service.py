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
import mock
from oslo_utils import uuidutils

from esi_leap.common import statuses
from esi_leap.manager.service import ManagerService
from esi_leap.objects import lease
from esi_leap.objects import offer
from esi_leap.objects import owner_change
from esi_leap.tests import base


class TestService(base.TestCase):

    def setUp(self):
        super(TestService, self).setUp()

        self.test_offer = offer.Offer(
            resource_type='test_node',
            resource_uuid='abc',
            name="o",
            uuid=uuidutils.generate_uuid(),
            status=statuses.AVAILABLE,
            start_time=datetime.datetime(3000, 7, 16),
            end_time=datetime.datetime(4000, 7, 16),
            project_id='ownerid'
        )

        self.test_lease = lease.Lease(
            offer_uuid=self.test_offer.uuid,
            name='c',
            uuid=uuidutils.generate_uuid(),
            project_id='lesseeid',
            status=statuses.CREATED,
            start_time=datetime.datetime(3000, 7, 16),
            end_time=datetime.datetime(4000, 7, 16),
        )

        self.test_owner_change = owner_change.OwnerChange(
            resource_type='test_node',
            resource_uuid='abc',
            uuid=uuidutils.generate_uuid(),
            status=statuses.CREATED,
            start_time=datetime.datetime(3000, 7, 16),
            end_time=datetime.datetime(4000, 7, 16),
            from_project_id='ownerid',
            to_project_id='ownerid2',
        )

    @mock.patch('esi_leap.objects.lease.Lease.fulfill')
    @mock.patch('oslo_utils.timeutils.utcnow')
    @mock.patch('esi_leap.objects.lease.Lease.get_all')
    def test__fulfill_leases(self, mock_ga, mock_utcnow, mock_fulfill):
        mock_ga.return_value = [self.test_lease, self.test_lease]
        mock_utcnow.return_value = datetime.datetime(3500, 7, 16)

        s = ManagerService()
        s._fulfill_leases()

        assert mock_fulfill.call_count == 2
        mock_ga.assert_called_once_with({
            'status': [statuses.CREATED]
        }, s._context)

    @mock.patch('esi_leap.objects.lease.Lease.expire')
    @mock.patch('oslo_utils.timeutils.utcnow')
    @mock.patch('esi_leap.objects.lease.Lease.get_all')
    def test__expire_leases(self, mock_ga, mock_utcnow, mock_expire):
        mock_ga.return_value = [self.test_lease, self.test_lease]
        mock_utcnow.return_value = datetime.datetime(5000, 7, 16)

        s = ManagerService()
        s._expire_leases()

        assert mock_expire.call_count == 2
        mock_ga.assert_called_once_with({
            'status': [statuses.ACTIVE, statuses.CREATED]
        }, s._context)

    @mock.patch('esi_leap.objects.offer.Offer.expire')
    @mock.patch('oslo_utils.timeutils.utcnow')
    @mock.patch('esi_leap.objects.offer.Offer.get_all')
    def test__expire_offers(self, mock_ga, mock_utcnow, mock_expire):
        mock_ga.return_value = [self.test_offer, self.test_offer]
        mock_utcnow.return_value = datetime.datetime(5000, 7, 16)

        s = ManagerService()
        s._expire_offers()

        assert mock_expire.call_count == 2
        mock_ga.assert_called_once_with({
            'status': statuses.AVAILABLE
        }, s._context)

    @mock.patch('esi_leap.objects.owner_change.OwnerChange.fulfill')
    @mock.patch('oslo_utils.timeutils.utcnow')
    @mock.patch('esi_leap.objects.owner_change.OwnerChange.get_all')
    def test__fulfill_owner_changes(self, mock_ga, mock_utcnow, mock_fulfill):
        mock_ga.return_value = [self.test_owner_change, self.test_owner_change]
        mock_utcnow.return_value = datetime.datetime(3500, 7, 16)

        s = ManagerService()
        s._fulfill_owner_changes()

        assert mock_fulfill.call_count == 2
        mock_ga.assert_called_once_with({
            'status': [statuses.CREATED]
        }, s._context)

    @mock.patch('esi_leap.objects.owner_change.OwnerChange.expire')
    @mock.patch('oslo_utils.timeutils.utcnow')
    @mock.patch('esi_leap.objects.owner_change.OwnerChange.get_all')
    def test__expire_owner_changes(self, mock_ga, mock_utcnow, mock_expire):
        mock_ga.return_value = [self.test_owner_change, self.test_owner_change]
        mock_utcnow.return_value = datetime.datetime(5000, 7, 16)

        s = ManagerService()
        s._expire_owner_changes()

        assert mock_expire.call_count == 2
        mock_ga.assert_called_once_with({
            'status': [statuses.ACTIVE, statuses.CREATED]
        }, s._context)
