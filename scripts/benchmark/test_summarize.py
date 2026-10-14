import csv
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from summarize import summarize


class SummarizeTest(unittest.TestCase):
    def write_data(self, rows):
        temp = tempfile.NamedTemporaryFile(mode="w", newline="", delete=False)
        writer = csv.DictWriter(temp, fieldnames=[
            "configuration", "repetition", "attach_mode", "packet_size_bytes",
            "duration_seconds", "packets", "victim_cpu_percent", "cycles",
            "instructions", "ringbuf_lost",
        ])
        writer.writeheader()
        writer.writerows(rows)
        temp.close()
        self.addCleanup(pathlib.Path(temp.name).unlink, missing_ok=True)
        return temp.name

    def complete_rows(self):
        rows = []
        for config in ("pass", "xdp_drop", "nftables_drop", "xdp_telemetry"):
            mode = "native" if config.startswith("xdp_") else "none"
            for repetition in range(1, 6):
                rows.append({
                    "configuration": config,
                    "repetition": repetition,
                    "attach_mode": mode,
                    "packet_size_bytes": 64,
                    "duration_seconds": 10,
                    "packets": 1000 * repetition,
                    "victim_cpu_percent": 20 + repetition,
                    "cycles": 100000 * repetition,
                    "instructions": 50000 * repetition,
                    "ringbuf_lost": repetition if config == "xdp_telemetry" else 0,
                })
        return rows

    def test_summarizes_complete_repeated_matrix(self):
        output = summarize(self.write_data(self.complete_rows()))
        self.assertIn("configuration,repetitions,attach_mode,packet_size_bytes", output)
        self.assertIn("pass,5,none,64,10.00,300.00", output)
        self.assertIn("xdp_telemetry,5,native,64,10.00,300.00", output)

    def test_rejects_incomplete_configuration(self):
        rows = self.complete_rows()[:-1]
        with self.assertRaisesRegex(ValueError, "xdp_telemetry: found 4 runs"):
            summarize(self.write_data(rows))

    def test_rejects_mixed_packet_sizes(self):
        rows = self.complete_rows()
        rows[-1]["packet_size_bytes"] = 128
        with self.assertRaisesRegex(ValueError, "packet_size_bytes must be identical"):
            summarize(self.write_data(rows))


if __name__ == "__main__":
    unittest.main()
