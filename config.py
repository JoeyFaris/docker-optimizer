import yaml
from dataclasses import dataclass
from typing import List

@dataclass
class AnalyzerConfig:
    ignore_paths: List[str]
    size_threshold_mb: int
    cache_results: bool
    parallel_analysis: bool

def load_config(config_path: str = "analyzer_config.yml") -> AnalyzerConfig:
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    return AnalyzerConfig(**config_data) 