"""The dashboard investigation flow crosses HTTP, durable state and two AI
phases. These tests keep the model and endpoint fake while exercising that
boundary, including retries, approval binding and restart recovery."""

from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

import investigations
import main
from remediation import Decision, Outcome, Proposal
from store import Store


class InvestigationApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.insert_device("dev-1", "public-key", "OFFICE-PC", "Windows 11", "1.0")
        self.old_store = main.store
        main.store = self.store
        investigations.configure(self.store)

    def tearDown(self):
        main.store = self.old_store
        investigations.configure(self.old_store)
        self.store._db.close()

    @staticmethod
    def request(request_id="request-1", problem="Nothing prints from this computer."):
        return main.CreateInvestigationRequest(
            deviceId="dev-1", problem=problem, requestId=request_id)

    async def create(self, request_id="request-1", problem="Nothing prints from this computer."):
        with mock.patch.object(investigations, "DRIVER_AVAILABLE", True), \
             mock.patch.object(investigations, "schedule_start") as schedule:
            response = await main.create_investigation(
                self.request(request_id, problem), operator="alice")
        return response, schedule

    async def test_submission_is_durable_and_idempotent(self):
        first, first_schedule = await self.create()
        second, second_schedule = await self.create()

        self.assertEqual(first, second)
        first_schedule.assert_called_once_with(first["investigationId"])
        second_schedule.assert_not_called()
        row = self.store.get_investigation(first["investigationId"])
        self.assertEqual(row["status"], "queued")
        self.assertEqual(len(self.store.get_investigation_events(row["investigation_id"])), 1)

    async def test_a_request_id_cannot_be_reused_for_different_input(self):
        await self.create()
        with self.assertRaises(HTTPException) as raised:
            await self.create(problem="This computer is very slow today.")
        self.assertEqual(raised.exception.status_code, 409)

    async def test_list_and_detail_match_the_frontend_contract(self):
        created, _ = await self.create()
        investigation_id = created["investigationId"]
        result = await main.list_investigations(
            page=1, pageSize=30, search="", status=None, operator="alice")
        detail = await main.get_investigation(investigation_id, operator="alice")

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["hostname"], "OFFICE-PC")
        self.assertEqual(detail["investigationId"], investigation_id)
        self.assertEqual(detail["status"], "queued")
        self.assertIsNone(detail["proposal"])

    async def _awaiting_proposal(self):
        created, _ = await self.create()
        investigation_id = created["investigationId"]
        proposal = Proposal(
            investigation_id=investigation_id, device_id="dev-1", hostname="OFFICE-PC",
            decision=Decision.PROPOSED, repair="start_service",
            arguments={"service_name": "Spooler"},
            script="Start-Service -Name 'Spooler' -ErrorAction Stop; \"started Spooler\"",
            reasoning="The Spooler service is stopped.",
            expected_effect="The printing service starts.", risk="Low.",
            verification_describes="the service is running")
        from remediation import sha256_hex
        proposal.script_sha256 = sha256_hex(proposal.script)
        investigations._store_proposal(investigation_id, "dev-1", proposal)
        self.store.set_investigation_status(investigation_id, "awaiting_approval")
        row = self.store.get_current_proposal(investigation_id)
        request = main.InvestigationDecisionRequest(
            proposalId=row["proposal_id"], proposalHash=row["proposal_hash"],
            deviceId="dev-1", decision="approve")
        return investigation_id, row, request

    async def test_approval_schedules_exactly_one_apply(self):
        investigation_id, _, request = await self._awaiting_proposal()
        with mock.patch.object(investigations, "DRIVER_AVAILABLE", True), \
             mock.patch.object(investigations, "schedule_apply") as schedule:
            first = await main.decide_investigation(investigation_id, request, operator="alice")
            second = await main.decide_investigation(investigation_id, request, operator="alice")

        self.assertEqual(first["status"], "applying")
        self.assertEqual(second["status"], "applying")
        schedule.assert_called_once_with(investigation_id)

    async def test_conflicting_decision_is_rejected(self):
        investigation_id, row, request = await self._awaiting_proposal()
        with mock.patch.object(investigations, "DRIVER_AVAILABLE", True), \
             mock.patch.object(investigations, "schedule_apply"):
            await main.decide_investigation(investigation_id, request, operator="alice")

        reject = main.InvestigationDecisionRequest(
            proposalId=row["proposal_id"], proposalHash=row["proposal_hash"],
            deviceId="dev-1", decision="reject")
        with self.assertRaises(HTTPException) as raised:
            await main.decide_investigation(investigation_id, reject, operator="alice")
        self.assertEqual(raised.exception.status_code, 409)

    async def test_changed_durable_proposal_invalidates_the_binding(self):
        investigation_id, row, request = await self._awaiting_proposal()
        self.store._db.execute(
            "UPDATE investigation_proposals SET risk='a different impact' WHERE proposal_id=?",
            (row["proposal_id"],))
        self.store._db.commit()

        with self.assertRaises(HTTPException) as raised:
            await main.decide_investigation(investigation_id, request, operator="alice")
        self.assertEqual(raised.exception.status_code, 409)

    async def test_expired_proposal_cannot_be_approved(self):
        investigation_id, row, request = await self._awaiting_proposal()
        self.store._db.execute(
            "UPDATE investigation_proposals SET expires_at=? WHERE proposal_id=?",
            (time.time() - 1, row["proposal_id"]))
        self.store._db.commit()
        # The binding also covers expiry, so use the recomputed hash to reach
        # the explicit expiry check rather than failing earlier as stale.
        current = self.store.get_current_proposal(investigation_id)
        proposal = investigations._proposal_from_row(
            investigation_id, "dev-1", "OFFICE-PC", current)
        current_hash = investigations._compute_proposal_hash(
            investigation_id, "dev-1", proposal, current["expires_at"])
        self.store._db.execute(
            "UPDATE investigation_proposals SET proposal_hash=? WHERE proposal_id=?",
            (current_hash, row["proposal_id"]))
        self.store._db.commit()
        request.proposal_hash = current_hash

        with self.assertRaises(HTTPException) as raised:
            await main.decide_investigation(investigation_id, request, operator="alice")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("expired", raised.exception.detail.lower())


class InvestigationWorkerTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.insert_device("dev-1", "public-key", "OFFICE-PC", "Windows 11", "1.0")
        investigations.configure(self.store)

    def tearDown(self):
        self.store._db.close()

    def create(self, suffix="1"):
        row, _ = self.store.create_investigation(
            f"inv-{suffix}", "dev-1", "Nothing prints from this computer.",
            "alice", f"request-{suffix}")
        return row["investigation_id"]

    def test_diagnosis_persists_evidence_and_a_reviewable_proposal(self):
        investigation_id = self.create()
        step = SimpleNamespace(
            diagnostic="service_status", arguments={"service_name": "Spooler"},
            ok=True, data={"status": "Stopped"}, detail="service_status: ok")
        completed = SimpleNamespace(
            steps=[step], concluded=True,
            finding="FINDING: Spooler is stopped.\nCONFIDENCE: high\nSUGGESTED ACTION: start it.",
            stopped_because="concluded",
            evidence=lambda: [{"diagnostic": "service_status",
                               "checkSucceeded": True, "output": {"status": "Stopped"}}])
        proposal = Proposal(
            investigation_id=investigation_id, device_id="dev-1", hostname="OFFICE-PC",
            decision=Decision.PROPOSED, repair="start_service",
            arguments={"service_name": "Spooler"},
            script="Start-Service -Name 'Spooler' -ErrorAction Stop; \"started Spooler\"",
            reasoning="The evidence shows Spooler is stopped.",
            expected_effect="Spooler starts.", risk="Low.",
            verification_describes="the service is running")
        from remediation import sha256_hex
        proposal.script_sha256 = sha256_hex(proposal.script)

        fake_investigator = mock.Mock()
        fake_investigator.investigate.return_value = completed
        fake_planner = mock.Mock()
        fake_planner.propose.return_value = proposal
        with mock.patch.object(investigations, "_client", return_value=object()), \
             mock.patch.object(investigations, "_model", return_value=object()), \
             mock.patch.object(investigations, "Investigator", return_value=fake_investigator), \
             mock.patch.object(investigations, "Planner", return_value=fake_planner):
            investigations._run_diagnosis_and_planning(investigation_id)

        row = self.store.get_investigation(investigation_id)
        self.assertEqual(row["status"], "awaiting_approval")
        self.assertEqual(row["finding"], "Spooler is stopped.")
        self.assertEqual(row["confidence"], "high")
        self.assertEqual(len(self.store.get_investigation_evidence(investigation_id)), 1)
        self.assertTrue(investigations.proposal_hash_matches(
            investigation_id, "dev-1", self.store.get_current_proposal(investigation_id)))

    def test_approved_repair_persists_verified_outcome(self):
        investigation_id = self.create()
        proposal = Proposal(
            investigation_id=investigation_id, device_id="dev-1", hostname="OFFICE-PC",
            decision=Decision.PROPOSED, repair="start_service",
            arguments={"service_name": "Spooler"}, script="script", script_sha256="hash")
        investigations._store_proposal(investigation_id, "dev-1", proposal)
        row = self.store.get_current_proposal(investigation_id)
        self.store.record_proposal_decision(row["proposal_id"], "alice", "approve")
        self.store.set_investigation_status(investigation_id, "applying")
        applier = mock.Mock()
        applier.apply.return_value = Outcome(
            applied=True, resolved=True, detail="the service is running", job_id="job-1")

        with mock.patch.object(investigations, "_client", return_value=object()), \
             mock.patch.object(investigations, "Applier", return_value=applier):
            investigations._run_apply(investigation_id)

        row = self.store.get_investigation(investigation_id)
        self.assertEqual(row["status"], "resolved")
        self.assertIn('"jobId": "job-1"', row["outcome"])

    def test_restart_requeues_diagnosis_and_resumes_only_approved_repairs(self):
        diagnosing = self.create("diagnosing")
        self.store.set_investigation_status(diagnosing, "planning")
        self.store.insert_investigation_evidence(
            diagnosing, "disk_usage", {}, True, {"percentFree": 50}, None)

        applying = self.create("applying")
        proposal = Proposal(
            investigation_id=applying, device_id="dev-1", hostname="OFFICE-PC",
            decision=Decision.PROPOSED, repair="start_service",
            arguments={"service_name": "Spooler"}, script="script", script_sha256="hash")
        investigations._store_proposal(applying, "dev-1", proposal)
        proposal_row = self.store.get_current_proposal(applying)
        self.store.record_proposal_decision(proposal_row["proposal_id"], "alice", "approve")
        self.store.set_investigation_status(applying, "verifying")

        work = self.store.recover_investigations()

        self.assertCountEqual(work, [(diagnosing, "start"), (applying, "apply")])
        self.assertEqual(self.store.get_investigation(diagnosing)["status"], "queued")
        self.assertEqual(self.store.get_investigation_evidence(diagnosing), [])
        self.assertEqual(self.store.get_investigation(applying)["status"], "applying")


if __name__ == "__main__":
    unittest.main()
