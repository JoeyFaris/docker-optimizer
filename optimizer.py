#!/usr/bin/env python3
# Import required libraries
import docker
from typing import List, Dict, Optional
import sys
import inquirer
from inquirer import themes
from container_manager import ContainerManager
import subprocess
import platform
import re
import time
import signal

class DockerAnalyzer:
    """Main class for analyzing Docker images and containers"""
    def __init__(self):
        # Try to connect to Docker daemon, first using client config then environment
        try:
            self.client = docker.from_client()
        except:
            try:
                self.client = docker.from_env()
            except docker.errors.DockerException as e:
                sys.exit(1)
        # Initialize container manager to handle container lifecycle
        self.container_manager = ContainerManager(self.client)
        
    def list_images(self) -> List[str]:
        """List all available Docker images"""
        try:
            images = self.client.images.list()
            return [f"{image.tags[0] if image.tags else 'none:none'}" for image in images]
        except docker.errors.APIError as e:
            sys.exit(1)
            
    def get_image_filesystem(self, image_name: str) -> Optional[Dict]:
        """Get filesystem information for selected image"""
        # Create or get existing container
        container = self.container_manager.ensure_container_exists(image_name)
        if not container:
            return None
            
        try:
            # Get list of all files in container
            exec_command = container.exec_run('find / -type f')
            if exec_command.exit_code != 0:
                return None
                
            files = exec_command.output.decode('utf-8').split('\n')
            
            return {
                'files': [f for f in files if f],
                'total_files': len(files)
            }
        except docker.errors.APIError:
            return None

    def get_unused_files(self, image_name: str) -> Optional[Dict]:
        """Get information about unused files in the image"""
        container = self.container_manager.ensure_container_exists(image_name)
        if not container:
            return None
        
        try:
            # Get all files in container
            all_files_cmd = container.exec_run('find / -type f')
            if all_files_cmd.exit_code != 0:
                return None
                
            all_files = set(all_files_cmd.output.decode('utf-8').split('\n'))
            
            # Get files currently in use via lsof
            used_files_cmd = container.exec_run('lsof -F n')
            used_files = set()
            
            if used_files_cmd.exit_code == 0:
                used_files = set(
                    line[1:] for line in used_files_cmd.output.decode('utf-8').split('\n')
                    if line.startswith('n/')
                )
            
            # Get files mapped by running processes
            proc_files = set()
            ps_cmd = container.exec_run('ps aux')
            if ps_cmd.exit_code == 0:
                processes = ps_cmd.output.decode('utf-8').split('\n')[1:]
                for proc in processes:
                    if proc:
                        try:
                            pid = proc.split()[1]
                            maps_cmd = container.exec_run(f'cat /proc/{pid}/maps')
                            if maps_cmd.exit_code == 0:
                                proc_files.update(
                                    line.split()[-1] for line in maps_cmd.output.decode('utf-8').split('\n')
                                    if line and not line.endswith(' 0')
                                )
                        except IndexError:
                            continue
            
            used_files.update(proc_files)
            
            # Define system paths to exclude from unused files analysis
            system_paths = {
                '/bin', '/sbin', '/lib', '/lib64', '/usr/bin', '/usr/sbin',
                '/usr/lib', '/etc', '/var/log', '/var/run', '/dev', '/proc', '/sys'
            }
            
            # Calculate truly unused files (excluding system paths)
            unused_files = {
                f for f in all_files 
                if f and not any(f.startswith(path) for path in system_paths)
                and f not in used_files
            }
            
            return {
                'all_files': len(all_files),
                'used_files': len(used_files),
                'unused_files': sorted(list(unused_files)),
                'total_unused': len(unused_files)
            }
        except docker.errors.APIError:
            return None
        except Exception:
            return None

    def __del__(self):
        """Cleanup when the analyzer is destroyed"""
        if hasattr(self, 'container_manager'):
            self.container_manager.cleanup()

def get_container_pid(container_id: str) -> Optional[str]:
    """Get the main process ID (PID) of a Docker container."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Pid}}", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        pid = result.stdout.strip()
        return pid
    except:
        return None

def run_trace_command(pid):
    """Run system call tracing (dtrace on macOS, strace on Linux)"""
    try:
        if platform.system() == 'Darwin':
            # macOS: Use dtrace to trace system calls
            cmd = [
                'sudo', 'dtrace', 
                '-o', 'dtrace_output.txt',
                '-n', 
                f'''
                syscall::open*:entry,
                syscall::stat*:entry,
                syscall::access*:entry
                /pid == {pid}/
                {{
                    printf("%s %s\\n", probefunc, copyinstr(arg0));
                }}
                '''
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=30)
                return True
            except subprocess.TimeoutExpired:
                process.terminate()
                return True
                
        else:
            # Linux: Use strace to trace system calls
            cmd = ['sudo', 'strace', '-f', '-p', str(pid), '-o', 'strace_output.log']
        
        process = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return True
    except subprocess.TimeoutExpired:
        return True
    except subprocess.CalledProcessError:
        return False
    except KeyboardInterrupt:
        return True
    except:
        return False

def parse_trace_output() -> set:
    """Parse the dtrace/strace output to extract file paths."""
    file_paths = set()
    try:
        # Choose output file based on OS
        filename = 'dtrace_output.txt' if platform.system() == 'Darwin' else 'strace_output.log'
        
        with open(filename, "r") as file:
            for line in file:
                if platform.system() == 'Darwin':
                    # Parse dtrace output
                    if 'open' in line or 'stat' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            file_paths.add(parts[1])
                else:
                    # Parse strace output
                    match = re.search(r'openat\(.*?, "([^"]+)",', line)
                    if match:
                        file_paths.add(match.group(1))
    except:
        pass
    return file_paths

def get_available_images() -> List[tuple[str, str]]:
    """Get list of available Docker images with their sizes."""
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        images = []
        for line in result.stdout.strip().split('\n'):
            if line:
                image, size = line.split('\t')
                images.append((image, size))
        return images
    except:
        return []

def analyze_container_files(container) -> set:
    """Analyze files being used in the container, excluding node_modules"""
    used_files = set()
    
    try:
        # Find all relevant source files, excluding certain directories
        app_cmd = container.exec_run(
            'find /app -type f '
            '\( '
            '-name "*.js" -o '
            '-name "*.jsx" -o '
            '-name "*.ts" -o '
            '-name "*.tsx" -o '
            '-name "*.json" -o '
            '-name "*.html" -o '
            '-name "*.css" '
            '\) '
            '-not -path "*/node_modules/*" '
            '-not -path "*/dist/*" '
            '-not -path "*/.git/*" '
        )
        
        if app_cmd.exit_code == 0:
            app_files = app_cmd.output.decode('utf-8').split('\n')
            used_files.update(f for f in app_files if f)
        
        # Categorize files by type
        source_files = {f for f in used_files if f.endswith(('.js', '.jsx', '.ts', '.tsx'))}
        config_files = {f for f in used_files if f.endswith('.json')}
        style_files = {f for f in used_files if f.endswith(('.css', '.html'))}
        
        return used_files
        
    except:
        return set()

def main():
    """Main function to run the Docker Image Analyzer"""
    print("\n🔍 Docker Image Analyzer")
    print("------------------------")
    print("Note: This tool requires administrator privileges to analyze container behavior.")
    print("You can press Ctrl+C at any time to stop the analysis.")

    # Get list of available Docker images
    images = get_available_images()
    if not images:
        print("No Docker images found. Please pull some images first.")
        return

    # Create selection menu for images
    choices = [(f"{image} ({size})", image) for image, size in images]
    questions = [
        inquirer.List('image',
                     message="Select a Docker image to analyze",
                     choices=choices,
                     carousel=True)
    ]

    try:
        # Prompt user to select an image
        answers = inquirer.prompt(questions, theme=themes.GreenPassion())
        if not answers:
            print("\nAnalysis cancelled.")
            return

        selected_image = answers['image']
        
        # Initialize analyzer and create container
        analyzer = DockerAnalyzer()
        container = analyzer.container_manager.ensure_container_exists(selected_image)
        if not container:
            print("Failed to create/get container")
            return
            
        # Analyze container files
        used_files = analyze_container_files(container)
        
        # Display results
        if used_files:
            print("\nFiles being used by the container:")
            for file in sorted(used_files):
                print(file)
            print(f"\nTotal files in use: {len(used_files)}")
        else:
            print("No files were found in use")
            
    except KeyboardInterrupt:
        print("\nAnalysis cancelled by user")
    except Exception as e:
        print(f"Unexpected error during analysis: {e}")
    finally:
        # Cleanup
        if 'analyzer' in locals():
            analyzer.__del__()

if __name__ == "__main__":
    main()