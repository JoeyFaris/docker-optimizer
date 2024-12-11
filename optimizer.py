#!/usr/bin/env python3
import docker
from typing import Dict, Optional, List, Tuple
import sys
import inquirer
from inquirer import themes
from container_manager import ContainerManager
from image_analyzer import ImageAnalyzer
from progress_reporter import ProgressReporter
from filesystem_analyzer import FilesystemAnalyzer
from security_scanner import SecurityScanner
from utils import display_analysis_results
from file_access_tracker import FileAccessTracker
from dataclasses import dataclass
import os

@dataclass
class OptimizationSuggestion:
    category: str
    description: str
    potential_savings: int  # in bytes
    priority: int  # 1-5, where 1 is highest priority

class DockerAnalyzer:
    """Main class for analyzing Docker images and containers"""
    def __init__(self):
        # Try to connect to Docker daemon
        try:
            self.client = docker.from_client()
        except:
            try:
                self.client = docker.from_env()
            except docker.errors.DockerException as e:
                sys.exit(1)
        self.container_manager = ContainerManager(self.client)
        
    def analyze_image(self, image_name: str) -> Dict:
        """Comprehensive analysis of a Docker image"""
        progress = ProgressReporter()
        progress.start_analysis(5)

        # Step 1: Layer Analysis
        progress.next_step("Analyzing image layers")
        analyzer = ImageAnalyzer(self.client)
        layer_info = analyzer.analyze_layers(image_name)
        
        # Step 2: Create container and analyze filesystem
        container = self.container_manager.ensure_container_exists(image_name)
        if not container:
            return {}
            
        progress.next_step("Analyzing filesystem")
        fs_analyzer = FilesystemAnalyzer(container)
        filesystem_info = self._analyze_filesystem(fs_analyzer)
        
        # Step 3: Security Analysis
        progress.next_step("Performing security scan")
        security_scanner = SecurityScanner(self.client, container)
        security_info = security_scanner.scan_security(image_name)
        
        # Step 4: File Access Tracking
        progress.next_step("Tracking file access patterns")
        access_tracker = FileAccessTracker(container.id)
        file_access = access_tracker.get_accessed_files()
        
        # Add optimization analysis
        progress.next_step("Analyzing optimization opportunities")
        optimization_suggestions = self._analyze_optimization_opportunities(layer_info, filesystem_info)
        
        progress.finish()
        
        return {
            'layer_analysis': layer_info,
            'unused_files': filesystem_info,
            'security': security_info,
            'file_access': file_access,
            'optimization_suggestions': optimization_suggestions
        }

    def _analyze_filesystem(self, fs_analyzer: FilesystemAnalyzer) -> Optional[Dict]:
        """Analyze filesystem and calculate usage"""
        try:
            all_files_with_size = fs_analyzer.get_all_files_with_size()
            if not all_files_with_size:
                print("Warning: No files found in container")
                return None
                
            all_files = {path for path, _ in all_files_with_size}
            
            # Get used files using the comprehensive method
            used_files = fs_analyzer.get_all_used_files()
            
            # Filter and calculate unused files
            unused_files = {
                (path, size) for path, size in all_files_with_size 
                if path and not fs_analyzer.is_system_path(path) and path not in used_files
            }
            
            total_size = sum(size for _, size in all_files_with_size)
            unused_size = sum(size for _, size in unused_files)
            
            result = {
                'all_files': len(all_files),
                'total_size': total_size,
                'used_files': len(used_files),
                'unused_files': sorted(path for path, _ in unused_files),
                'total_unused': len(unused_files),
                'unused_size': unused_size
            }
            
            # Debug output
            print(f"Debug: Found {len(all_files)} total files")
            print(f"Debug: Found {len(used_files)} used files")
            print(f"Debug: Found {len(unused_files)} unused files")
            
            return result
        except Exception as e:
            print(f"Error analyzing filesystem: {e}")
            return None

    def _analyze_optimization_opportunities(self, layer_info: Dict, filesystem_info: Dict) -> List[OptimizationSuggestion]:
        """Analyze and suggest optimization opportunities"""
        suggestions = []
        
        # Check for large files that might be removable
        if filesystem_info and 'unused_files' in filesystem_info:
            large_unused_files = [
                (path, size) for path, size in filesystem_info.get('unused_files', [])
                if size > 10 * 1024 * 1024  # Files larger than 10MB
            ]
            if large_unused_files:
                total_size = sum(size for _, size in large_unused_files)
                suggestions.append(OptimizationSuggestion(
                    category="Large Unused Files",
                    description=f"Found {len(large_unused_files)} large unused files that could be removed",
                    potential_savings=total_size,
                    priority=1
                ))

        # Check for layer optimization opportunities
        if layer_info:
            duplicate_files = self._find_duplicate_files_across_layers(layer_info)
            if duplicate_files:
                total_duplicate_size = sum(size for _, size in duplicate_files)
                suggestions.append(OptimizationSuggestion(
                    category="Layer Optimization",
                    description=f"Found {len(duplicate_files)} files duplicated across layers",
                    potential_savings=total_duplicate_size,
                    priority=2
                ))

        # Check for package manager cache
        if filesystem_info:
            package_cache_size = self._analyze_package_cache(filesystem_info)
            if package_cache_size > 0:
                suggestions.append(OptimizationSuggestion(
                    category="Package Cache",
                    description="Package manager cache could be cleared",
                    potential_savings=package_cache_size,
                    priority=3
                ))

        return suggestions

    def _find_duplicate_files_across_layers(self, layer_info: Dict) -> List[Tuple[str, int]]:
        """Find files that are duplicated across layers"""
        duplicates = []
        # Implementation would analyze layer_info to find duplicated files
        return duplicates

    def _analyze_package_cache(self, filesystem_info: Dict) -> int:
        """Analyze package manager cache size"""
        cache_paths = [
            '/var/cache/apt',
            '/var/lib/apt/lists',
            '/var/cache/yum',
            '/var/cache/dnf',
            '/root/.cache/pip'
        ]
        
        total_cache_size = 0
        for path in cache_paths:
            if path in filesystem_info.get('unused_files', []):
                # Get size from filesystem_info
                total_cache_size += filesystem_info['unused_files'][path]
                
        return total_cache_size

def main():
    """Main function to run the Docker Image Analyzer"""
    print("\n🔍 Docker Image Analyzer")
    print("------------------------")
    
    try:
        analyzer = DockerAnalyzer()
        images = analyzer.client.images.list()
        
        choices = [
            (f"{image.tags[0] if image.tags else 'none:none'} ({image.attrs['Size']/(1024*1024*1024):.2f}GB)", 
             image.tags[0] if image.tags else 'none:none') 
            for image in images
        ]
        
        questions = [
            inquirer.List('image',
                         message="Select a Docker image to analyze",
                         choices=choices,
                         carousel=True)
        ]

        answers = inquirer.prompt(questions, theme=themes.GreenPassion())
        if not answers:
            return

        analysis = analyzer.analyze_image(answers['image'])
        display_analysis_results(analysis)
            
    except KeyboardInterrupt:
        print("\nAnalysis cancelled by user")
    except Exception as e:
        print(f"Unexpected error during analysis: {e}")
    finally:
        if 'analyzer' in locals():
            analyzer.container_manager.cleanup()

if __name__ == "__main__":
    main()