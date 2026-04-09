import json
import csv
import os
from core.logger import get_logger, success, error

logger = get_logger()

class ExportManager:
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def to_json(self, data, filename="results.json"):
        try:
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            success(f"Results exported to JSON: {filepath}")
        except Exception as e:
            error(f"Failed to export JSON: {e}")

    def to_csv(self, data, filename="vulnerabilities.csv"):
        # Specifically for vuln findings
        try:
            filepath = os.path.join(self.output_dir, filename)
            if isinstance(data, list) and len(data) > 0:
                keys = data[0].keys()
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    dict_writer = csv.DictWriter(f, fieldnames=keys)
                    dict_writer.writeheader()
                    dict_writer.writerows(data)
                success(f"Results exported to CSV: {filepath}")
        except Exception as e:
            error(f"Failed to export CSV: {e}")
