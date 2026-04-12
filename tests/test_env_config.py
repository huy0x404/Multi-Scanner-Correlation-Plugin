import unittest

from mscp.env_config import get_telegram_config


class TestEnvConfig(unittest.TestCase):
    def test_missing_env_file(self) -> None:
        token, chat = get_telegram_config(".not_found_env")
        self.assertTrue(token is None or isinstance(token, str))
        self.assertTrue(chat is None or isinstance(chat, str))


if __name__ == "__main__":
    unittest.main()
