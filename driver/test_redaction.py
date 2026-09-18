"""No secrets in stored or displayed error text."""

import io
import json
import os
import unittest
import urllib.error
from unittest import mock

import model
import redaction


class RedactionTests(unittest.TestCase):
    def test_the_providers_masked_echo_of_a_key_is_removed(self):
        """What OpenAI returns for a rejected key."""
        text = ("Incorrect API key provided: sk-proj-****************************abcd. "
                "You can find your API key at https://platform.openai.com/account/api-keys.")
        cleaned = redaction.redact(text)
        self.assertNotIn("sk-proj", cleaned)
        self.assertNotIn("abcd", cleaned)
        self.assertIn("Incorrect API key provided", cleaned)

    def test_this_systems_own_credentials_are_removed(self):
        for secret in ("op_Zm9vYmFyYmF6cXV4cXV1eA", "enr_c2VjcmV0LXRva2VuLXZhbHVl",
                       "sk-abcdefghijklmnop"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, redaction.redact(f"failed with {secret} attached"))

    def test_credentials_in_headers_are_removed(self):
        for text in ("Authorization: Bearer abc.def.ghi123",
                     'X-API-Key: "op-ish-value-12345"', "x-api-key=someopaquekey123"):
            with self.subTest(text=text):
                cleaned = redaction.redact(text)
                self.assertIn(redaction.REDACTED, cleaned)
                self.assertNotIn("123", cleaned.replace(redaction.REDACTED, ""))

    def test_a_configured_secret_is_removed_whatever_its_shape(self):
        env = {"OPENAI_API_KEY": "unusual-format-key-9f8e7d",
               "SQUASH_OPERATOR_KEYS": "operator:plainpassword42,ai-driver:another-one-77"}
        with mock.patch.dict(os.environ, env, clear=False):
            cleaned = redaction.redact(
                "saw unusual-format-key-9f8e7d then plainpassword42 then another-one-77")
        for secret in ("unusual-format-key-9f8e7d", "plainpassword42", "another-one-77"):
            self.assertNotIn(secret, cleaned)

    def test_short_or_empty_configured_values_do_not_redact_ordinary_words(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "the",
                                          "SQUASH_OPERATOR_KEYS": "operator:"}):
            self.assertEqual(redaction.redact("the service is stopped"),
                             "the service is stopped")

    def test_ordinary_diagnostic_text_is_untouched(self):
        for text in ("Task-scheduler service is stopped",
                     "disk C: has 12.4 GB free",
                     "operator approved the proposed fix",
                     "model provider returned 429: Rate limit reached"):
            with self.subTest(text=text):
                self.assertEqual(redaction.redact(text), text)

    def test_nothing_in_nothing_out(self):
        self.assertIsNone(redaction.redact(None))
        self.assertEqual(redaction.redact(""), "")


class ProviderErrorTests(unittest.TestCase):
    def test_a_rejected_key_is_not_carried_into_the_error(self):
        body = json.dumps({"error": {"message":
            "Incorrect API key provided: sk-proj-AbCd****************************WxYz.",
            "type": "invalid_request_error", "code": "invalid_api_key"}}).encode()
        error = urllib.error.HTTPError(
            "https://api.openai.com/v1/chat/completions", 401, "Unauthorized",
            {}, io.BytesIO(body))
        message = model._provider_message(error)
        self.assertIn("401", message)
        self.assertNotIn("sk-proj", message)
        self.assertNotIn("WxYz", message)


if __name__ == "__main__":
    unittest.main()
