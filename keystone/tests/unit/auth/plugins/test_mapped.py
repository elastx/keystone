# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock
import uuid

from keystone.auth.plugins import mapped
from keystone.federation import constants as federation_constants
from keystone.tests import unit


class TestHandleScopedToken(unit.TestCase):
    """Tests for the handle_scoped_token security fix.

    Verify that rescoping a federated token preserves the original
    token's expires_at rather than falling back to a fresh TTL.
    Without the fix, an attacker can extend their session indefinitely
    by rescoping before expiry, bypassing IdP-level account revocation.
    """

    def setUp(self):
        super().setUp()
        self.federation_api = mock.Mock()
        self.identity_api = mock.Mock()
        mapping_ref = {'id': uuid.uuid4().hex}
        self.federation_api.get_mapping_from_idp_and_protocol.return_value = (
            mapping_ref
        )

    @mock.patch(
        'keystone.auth.plugins.mapped.notifications'
        '.send_saml_audit_notification',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_mapped_group_ids',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.assert_enabled_identity_provider',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_expiration', autospec=True
    )
    def test_handle_scoped_token_preserves_expires_at(
        self,
        mock_validate_exp,
        mock_assert_idp,
        mock_validate_groups,
        mock_notify,
    ):
        """Rescoped federated token must inherit original expiry (not fresh TTL).

        This is the security regression test for the authentication expiry
        bypass vulnerability: handle_scoped_token must include expires_at in
        the returned response_data so that issue_token() does not fall back to
        default_expire_time().
        """
        original_expiry = '2026-04-26T08:59:30.000000Z'
        token = self._make_federated_token_mock(original_expiry)

        result = mapped.handle_scoped_token(
            token, self.federation_api, self.identity_api
        )

        self.assertIn('expires_at', result)
        self.assertEqual(original_expiry, result['expires_at'])

    @mock.patch(
        'keystone.auth.plugins.mapped.notifications'
        '.send_saml_audit_notification',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_mapped_group_ids',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.assert_enabled_identity_provider',
        autospec=True,
    )
    @mock.patch(
        'keystone.auth.plugins.mapped.utils.validate_expiration', autospec=True
    )
    def test_handle_scoped_token_returns_federation_metadata(
        self,
        mock_validate_exp,
        mock_assert_idp,
        mock_validate_groups,
        mock_notify,
    ):
        """Rescoped federated token still returns required federation data."""
        token = self._make_federated_token_mock('2026-04-26T08:59:30.000000Z')

        result = mapped.handle_scoped_token(
            token, self.federation_api, self.identity_api
        )

        self.assertEqual(token.user_id, result['user_id'])
        self.assertEqual(
            token.identity_provider_id,
            result[federation_constants.IDENTITY_PROVIDER],
        )
        self.assertEqual(
            token.protocol_id, result[federation_constants.PROTOCOL]
        )
        self.assertIsInstance(result['group_ids'], list)

    def _make_federated_token_mock(self, expires_at):
        token = mock.Mock()
        token.audit_id = uuid.uuid4().hex
        token.user_id = uuid.uuid4().hex
        token.identity_provider_id = 'test-idp'
        token.protocol_id = 'mapped'
        token.federated_groups = [{'id': uuid.uuid4().hex}]
        token.expires_at = expires_at
        return token
