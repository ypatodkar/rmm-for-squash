import unittest

from jobs import JobStore
from store import Store


class JobHistoryTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.jobs = JobStore(self.store)
        for index in range(76):
            self.store.insert_job({
                "job_id": f"job-{index:03}",
                "device_id": "device-a" if index % 2 == 0 else "device-b",
                "script": "Get-Service" if index % 3 == 0 else "hostname",
                "timeout_seconds": 30,
                "state": "Failed" if index % 5 == 0 else "Completed",
                # Equal timestamps exercise the secondary sort key.
                "created_at": 1000,
            })

    def tearDown(self):
        self.store._db.close()

    def test_pages_cover_history_without_overlap(self):
        pages = [self.jobs.page(page, 30) for page in (1, 2, 3)]
        self.assertEqual([len(page["items"]) for page in pages], [30, 30, 16])
        ids = [job["jobId"] for page in pages for job in page["items"]]
        self.assertEqual(len(set(ids)), 76)
        self.assertEqual(ids, [f"job-{i:03}" for i in reversed(range(76))])
        self.assertEqual(pages[0]["total"], 76)
        self.assertEqual(pages[0]["totalPages"], 3)

    def test_combined_filters_search_entire_history(self):
        result = self.jobs.page(1, 30, state="Failed", device_id="device-a",
                                search="  GET-service  ")
        self.assertEqual(result["total"], 3)
        self.assertEqual([j["jobId"] for j in result["items"]],
                         ["job-060", "job-030", "job-000"])

    def test_literal_search_and_empty_result(self):
        for search in ("%", "_", "' OR 1=1 --"):
            result = self.jobs.page(5, 30, search=search)
            self.assertEqual(result["items"], [])
            self.assertEqual(result["total"], 0)
            self.assertEqual(result["page"], 1)
            self.assertEqual(result["totalPages"], 1)

    def test_page_is_clamped_after_results_shrink(self):
        result = self.jobs.page(99, 30, state="Failed")
        self.assertEqual(result["page"], 1)
        self.assertEqual(result["total"], 16)
        self.assertEqual(len(result["items"]), 16)


if __name__ == "__main__":
    unittest.main()
