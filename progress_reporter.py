from typing import Optional
import sys
import time

class ProgressReporter:
    def __init__(self):
        self.current_step = 0
        self.total_steps = 0
        self.start_time = None

    def start_analysis(self, total_steps: int):
        self.total_steps = total_steps
        self.start_time = time.time()
        print("\n🚀 Starting Docker Image Analysis")
        print("================================")

    def next_step(self, message: str):
        self.current_step += 1
        print(f"\n[{self.current_step}/{self.total_steps}] {message}")

    def report_progress(self, message: str):
        print(f"  → {message}")

    def finish(self):
        duration = time.time() - self.start_time
        print(f"\n✨ Analysis completed in {duration:.1f} seconds")
