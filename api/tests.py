from django.test import TestCase
from rest_framework.test import APIClient
from unittest.mock import patch
from api.mongo_db import users_collection, email_verifications_collection
from api.utils import DateTimeHelper


class EmailVerificationFlowTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		# Clean collections
		users_collection.delete_many({})
		email_verifications_collection.delete_many({})

	@patch('api.email_utils.EmailService.send_email_verification', return_value=True)
	def test_register_sends_verification_and_login_blocked(self, _mock_send):
		# Register user
		res = self.client.post('/api/register/', {
			'email': 'test@example.com',
			'username': 'tester',
			'password': 'StrongPass1!'
		}, format='json')
		self.assertEqual(res.status_code, 201)
		code = res.json()['data']['verification_code']

		# Attempt login before verify
		res_login = self.client.post('/api/login/', {
			'email': 'test@example.com',
			'password': 'StrongPass1!'
		}, format='json')
		self.assertEqual(res_login.status_code, 403)

		# Verify email
		res_verify = self.client.post('/api/verify-email/', {
			'email': 'test@example.com',
			'code': code
		}, format='json')
		self.assertEqual(res_verify.status_code, 200)

		# Login should now succeed
		res_login2 = self.client.post('/api/login/', {
			'email': 'test@example.com',
			'password': 'StrongPass1!'
		}, format='json')
		self.assertEqual(res_login2.status_code, 200)
