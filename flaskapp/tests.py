import unittest
from app import app, db
from flask_testing import TestCase
from flask_login import current_user
from app.models import User, Loan
import jwt
import json
from requests.auth import _basic_auth_str


class BaseTest(TestCase):
    def create_app(self):
        app.config.from_object("config.TestConfig")
        return app

    def setUp(self):
        db.create_all()
        user = User(username="customer1", email="customer1@test.com", type_of_user=0)
        user.set_password(password="customer1")
        db.session.add(user)
        user = User(username="customer2", email="customer2@test.com", type_of_user=0)
        user.set_password(password="customer2")
        db.session.add(user)
        user = User(username="admin", email="admin@test.com", type_of_user=2)
        user.set_password(password="admin")
        db.session.add(user)
        user = User(username="agent", email="agent@test.com", type_of_user=1)
        user.set_password(password="agent")
        db.session.add(user)
        loan = Loan(tenure=10, principle=1200, roi=12, user=1)
        loan.emicalc()
        db.session.add(loan)
        loan = Loan(tenure=12, principle=1500, roi=14, user=2)
        loan.emicalc()
        db.session.add(loan)
        self.assertEqual(app.debug, True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()


class FlaskTestCase(BaseTest):
    def test_home_page(self):
        response = self.client.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_login_page(self):
        response = self.client.get(
            "/login", content_type="html/text", follow_redirects=True
        )
        self.assertTrue(b"Sign In" in response.data)

    def test_login_app(self):
        with self.client as c:
            response = c.post(
                "/login",
                data=dict(username="admin", password="admin"),
                follow_redirects=True,
            )
            self.assertTrue(b"PlaceHolder" in response.data)
            self.assertTrue(current_user.username == "admin")

    def test_register_app(self):
        with self.client as c:
            response = c.post(
                "/register",
                data=dict(
                    username="admin2",
                    email="admin2@test.com",
                    password="admin2",
                    passwordrep="admin2",
                ),
                follow_redirects=True,
            )
            self.assertTrue(
                b"Congratulations, you are now a registered user!" in response.data
            )

    def test_register_api(self):
        with self.client as c:
            response = c.post(
                "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/user",
                data=dict(
                    username="admin2", email="admin2@test.com", password="admin2"
                ),
                follow_redirects=True,
            )
            self.assertTrue({"message": "User admin2 created"}, response.data)

    def test_login_api(self):
        with self.client as c:
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/login",
                headers={"Authorization": _basic_auth_str("admin", "admin")},
                follow_redirects=True,
            )

            self.assertEqual(response.status_code, 200)

    def test_users_api(self):
        with self.client as c:
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/login",
                headers={"Authorization": _basic_auth_str("admin", "admin")},
                follow_redirects=True,
            )
            key = json.loads(response.data)["token"]
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/users",
                headers={"x-access-token": key},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b"admin@test.com" in response.data)
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/login",
                headers={"Authorization": _basic_auth_str("customer2", "customer2")},
                follow_redirects=True,
            )
            key = json.loads(response.data)["token"]
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/users",
                headers={"x-access-token": key},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 403)

    def test_loans_api(self):
        with self.client as c:
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/login",
                headers={"Authorization": _basic_auth_str("admin", "admin")},
                follow_redirects=True,
            )
            key = json.loads(response.data)["token"]
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/loans",
                headers={"x-access-token": key},
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b'"emi": 252.701785001305' in response.data)
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/login",
                headers={"Authorization": _basic_auth_str("customer2", "customer2")},
                follow_redirects=True,
            )
            key = json.loads(response.data)["token"]
            response = c.get(
                "/"
                + app.config["API_FOR"]
                + "/"
                + app.config["API_VERSION"]
                + "/loans",
                headers={"x-access-token": key},
                follow_redirects=True,
            )
            self.assertTrue(b'"emi": 477.238102478562' in response.data)
            self.assertFalse(b'"emi": 252.701785001305' in response.data)


if __name__ == "__main__":
    unittest.main()
