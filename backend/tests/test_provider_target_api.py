import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.main import app


class ProviderTargetApiTests(unittest.TestCase):
    def test_credentials_are_never_returned_and_can_be_updated_or_deleted(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        with patch.dict(
            "os.environ",
            {"AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY": key},
        ):
            client = TestClient(app)
            created = client.post(
                "/targets",
                json={
                    "name": "Credential API test",
                    "target_type": "openai_compatible",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "provider": "openai",
                    "model": "controlled-model",
                    "api_key": "first-controlled-key",
                },
            )
            self.assertEqual(created.status_code, 201)
            target_id = created.json()["target_id"]
            self.assertNotIn("api_key", created.json())
            self.assertNotIn("first-controlled-key", created.text)

            updated = client.put(
                f"/targets/{target_id}/credential",
                json={"api_key": "second-controlled-key"},
            )
            self.assertEqual(updated.status_code, 204)
            fetched = client.get(f"/targets/{target_id}")
            self.assertEqual(fetched.status_code, 200)
            self.assertNotIn("api_key", fetched.json())
            self.assertNotIn("second-controlled-key", fetched.text)

            deleted = client.delete(f"/targets/{target_id}/credential")
            self.assertEqual(deleted.status_code, 204)


if __name__ == "__main__":
    unittest.main()
