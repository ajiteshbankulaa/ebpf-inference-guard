import csv
import unittest
from collections import defaultdict
from pathlib import Path


class VethResultsTests(unittest.TestCase):
    def test_recorded_run_has_five_consistent_repetitions(self):
        path = Path(__file__).with_name("worker-veth-2026-10-14.csv")
        with path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))

        grouped = defaultdict(list)
        for row in rows:
            grouped[row["configuration"]].append(row)
            self.assertEqual(row["packet_size_bytes"], "64")
            self.assertEqual(row["packets"], "100000")
            self.assertGreater(float(row["ingress_pps"]), 0)

        self.assertEqual(
            set(grouped), {"pass", "xdp_drop", "nftables_drop", "xdp_telemetry"}
        )
        self.assertTrue(all(len(runs) == 5 for runs in grouped.values()))
        self.assertTrue(
            all(
                {row["repetition"] for row in runs} == {"1", "2", "3", "4", "5"}
                for runs in grouped.values()
            )
        )
        self.assertTrue(all(row["attach_mode"] == "none" for row in grouped["pass"]))
        self.assertEqual(
            sum(int(row["xdp_dropped"]) for row in grouped["xdp_drop"]), 500_000
        )
        self.assertEqual(
            sum(int(row["nft_dropped"]) for row in grouped["nftables_drop"]), 500_000
        )
        self.assertEqual(
            sum(int(row["ringbuf_events"]) for row in grouped["xdp_telemetry"]), 7_891
        )
        self.assertTrue(all(row["ringbuf_lost"] == "0" for row in grouped["xdp_telemetry"]))


if __name__ == "__main__":
    unittest.main()
