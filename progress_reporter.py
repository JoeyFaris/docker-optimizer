from typing import Optional
import sys
import time
from tqdm import tqdm

class ProgressReporter:
    def __init__(self):
        self.current_step = 0
        self.total_steps = 0
        self.start_time = None
        self.pbar = None

    def start_analysis(self, total_steps: int):
        self.total_steps = total_steps
        self.start_time = time.time()
        self.pbar = tqdm(total=total_steps, desc="🚀 Analyzing Docker Image")
        print("\n🚀 Starting Docker Image Analysis")
        print("================================")

    def next_step(self, message: str):
        self.current_step += 1
        self.pbar.set_description(f"🔍 {message}")
        self.pbar.update(1)

    def report_progress(self, message: str):
        print(f"  → {message}")

    def finish(self):
        if self.pbar:
            self.pbar.close()
        duration = time.time() - self.start_time
        print(f"\n✨ Analysis completed in {duration:.1f} seconds")
