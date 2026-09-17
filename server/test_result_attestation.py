"""A result is a claim until it is verified. These cover what happens when
the claim is false."""

import base64
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import auth
import main
import protocol


def keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(private.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
    return private, public


def sign(private, payload: bytes) -> str:
    return base64.b64encode(private.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()


class Job:
    def __init__(self, script):
        self.job_id = "job-1"
        self.script = script


class ResultAttestationTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = keypair()
        self.job = Job("Get-Process | Select-Object -First 3")
        self.device_id = "device-1"
        patcher = mock.patch.object(
            main, "store", mock.Mock(get_device=lambda _: {"public_key": self.public}))
        self.addCleanup(patcher.stop)
        patcher.start()

    def build(self, *, stdout="ok", exit_code=0, duration=12, script=None):
        script_sha = protocol.sha256_hex(script or self.job.script)
        attestation = protocol.result_attestation(
            self.job.job_id, script_sha, exit_code, duration, stdout, "")
        return {
            "jobId": self.job.job_id, "state": "Completed", "exitCode": exit_code,
            "stdout": stdout, "stderr": "", "durationMs": duration,
            "scriptSha256": script_sha, "signature": sign(self.private, attestation),
        }

    def test_genuine_result_is_accepted(self):
        ok, reason = main.verify_result(self.job, self.build(), self.device_id)
        self.assertTrue(ok, reason)

    def test_output_tampered_after_signing_is_rejected(self):
        payload = self.build(stdout="ok")
        payload["stdout"] = "everything is fine, nothing to see"
        ok, reason = main.verify_result(self.job, payload, self.device_id)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_exit_code_tampered_after_signing_is_rejected(self):
        payload = self.build(exit_code=1)
        payload["exitCode"] = 0
        ok, _ = main.verify_result(self.job, payload, self.device_id)
        self.assertFalse(ok)

    def test_result_for_a_different_script_is_rejected(self):
        payload = self.build(script="Remove-Item C:\\ -Recurse")
        ok, reason = main.verify_result(self.job, payload, self.device_id)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", reason)

    def test_signature_from_another_device_is_rejected(self):
        other_private, _ = keypair()
        payload = self.build()
        attestation = protocol.result_attestation(
            self.job.job_id, payload["scriptSha256"], 0, 12, "ok", "")
        payload["signature"] = sign(other_private, attestation)
        ok, reason = main.verify_result(self.job, payload, self.device_id)
        self.assertFalse(ok)
        self.assertIn("does not match", reason)

    def test_unsigned_result_is_rejected_when_attestation_is_required(self):
        payload = self.build()
        payload.pop("signature")
        with mock.patch.object(main, "REQUIRE_ATTESTATION", True):
            ok, reason = main.verify_result(self.job, payload, self.device_id)
        self.assertFalse(ok)
        self.assertIn("not signed", reason)

    def test_legacy_agent_is_tolerated_only_while_migrating(self):
        legacy = {"jobId": self.job.job_id, "state": "Completed", "exitCode": 0,
                  "stdout": "ok", "stderr": "", "durationMs": 12}

        with mock.patch.object(main, "REQUIRE_ATTESTATION", True):
            ok, _ = main.verify_result(self.job, legacy, self.device_id)
        self.assertFalse(ok)

        with mock.patch.object(main, "REQUIRE_ATTESTATION", False):
            ok, reason = main.verify_result(self.job, legacy, self.device_id)
        self.assertTrue(ok)
        self.assertIn("unverified", reason)


if __name__ == "__main__":
    unittest.main()
