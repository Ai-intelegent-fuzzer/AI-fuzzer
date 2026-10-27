import unittest

from app.adapters.manager import TargetManager
from app.adapters.models import TargetCreate


class TargetManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target_data = TargetCreate(
            name="Synthetic Groq target",
            target_type="openai_compatible",
            endpoint="https://api.groq.com/openai/v1/chat/completions",
            model="openai/gpt-oss-20b",
            provider="groq",
        )

    def test_target_can_be_created_listed_retrieved_and_deleted(self) -> None:
        manager = TargetManager()

        created = manager.create(self.target_data)

        self.assertEqual(manager.get(created.target_id), created)
        self.assertEqual(manager.list(), [created])
        self.assertTrue(manager.delete(created.target_id))
        self.assertIsNone(manager.get(created.target_id))

    def test_new_manager_has_no_targets_from_previous_manager(self) -> None:
        original_manager = TargetManager()
        created = original_manager.create(self.target_data)

        restarted_manager = TargetManager()

        self.assertIsNone(restarted_manager.get(created.target_id))


if __name__ == "__main__":
    unittest.main()
