#!/usr/bin/env python3
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
    def __init__(self):
        print("Initializing DockerAnalyzer...")
        try:
            self.client = docker.from_client()
            print("Connected to Docker using from_client()")
        except:
            try:
                self.client = docker.from_env()
                print("Connected to Docker using from_env()")
            except docker.errors.DockerException as e:
                print(f"Error connecting to Docker: {e}")
                sys.exit(1)
        self.container_manager = ContainerManager(self.client)
        
    def list_images(self) -> List[str]:
        """List all available Docker images"""
        print("Listing Docker images...")
        try:
            images = self.client.images.list()
            image_list = [f"{image.tags[0] if image.tags else 'none:none'}" for image in images]
            print(f"Found {len(image_list)} images")
            return image_list
        except docker.errors.APIError as e:
            print(f"Error connecting to Docker: {e}")
            sys.exit(1)
            
    def get_image_filesystem(self, image_name: str) -> Optional[Dict]:
        """Get filesystem information for selected image"""
        print(f"Getting filesystem info for image: {image_name}")
        
        container = self.container_manager.ensure_container_exists(image_name)
        if not container:
            return None
            
        try:
            # Get file list using exec
            print("Executing find command in container...")
            exec_command = container.exec_run('find / -type f')
            if exec_command.exit_code != 0:
                print("Error executing find command")
                return None
                
            files = exec_command.output.decode('utf-8').split('\n')
            print(f"Found {len(files)} files")
            
            return {
                'files': [f for f in files if f],  # Remove empty strings
                'total_files': len(files)
            }
        except docker.errors.APIError as e:
            print(f"Error analyzing image: {e}")
            return None

    def get_unused_files(self, image_name: str) -> Optional[Dict]:
        """Get information about unused files in the image"""
        print(f"Analyzing unused files in image: {image_name}")
        
        container = self.container_manager.ensure_container_exists(image_name)
        if not container:
            return None
        
        try:
            # Get all files
            print("Getting list of all files...")
            all_files_cmd = container.exec_run('find / -type f')
            if all_files_cmd.exit_code != 0:
                print("Error getting file list")
                return None
                
            all_files = set(all_files_cmd.output.decode('utf-8').split('\n'))
            
            # Get list of open files using lsof
            print("Checking for used files...")
            used_files_cmd = container.exec_run('lsof -F n')  # -F n outputs only filenames
            used_files = set()
            
            if used_files_cmd.exit_code == 0:
                used_files = set(
                    line[1:] for line in used_files_cmd.output.decode('utf-8').split('\n')
                    if line.startswith('n/')  # lsof lines starting with 'n' contain filenames
                )
            
            # Get files from running processes
            print("Checking process mappings...")
            proc_files = set()
            ps_cmd = container.exec_run('ps aux')
            if ps_cmd.exit_code == 0:
                processes = ps_cmd.output.decode('utf-8').split('\n')[1:]  # Skip header
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
            
            # Combine all used files
            used_files.update(proc_files)
            
            # Filter out common system files and directories that should be kept
            system_paths = {
                '/bin', '/sbin', '/lib', '/lib64', '/usr/bin', '/usr/sbin',
                '/usr/lib', '/etc', '/var/log', '/var/run', '/dev', '/proc', '/sys'
            }
            
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
        except docker.errors.APIError as e:
            print(f"Error analyzing image: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None

    def __del__(self):
        """Cleanup when the analyzer is destroyed"""
        if hasattr(self, 'container_manager'):
            self.container_manager.cleanup()

def get_container_pid(container_id: str) -> Optional[str]:
    """Get the main process ID (PID) of a Docker container."""
    try:
        print(f"Running docker inspect command for container: {container_id}")
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Pid}}", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        pid = result.stdout.strip()
        print(f"Docker inspect returned PID: {pid}")
        if pid == "0":
            print("Warning: Docker returned PID 0, container might not be running")
        return pid
    except subprocess.CalledProcessError as e:
        print(f"Error getting PID for container {container_id}: {e.stderr}")
        return None
    except Exception as e:
        print(f"Unexpected error getting container PID: {e}")
        return None

def run_trace_command(pid):
    try:
        if platform.system() == 'Darwin':  # MacOS
            print("\nℹ️  Admin privileges required to run dtrace")
            print("⌨️  Please enter your MacOS administrator password when prompted")
            print("   (Your password will not be visible as you type)\n")
            
            # Modified dtrace command with more detailed tracing
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
            
            print(f"Running dtrace command for PID: {pid}")
            print(f"Command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                print("\nCollecting data for 30 seconds...")
                stdout, stderr = process.communicate(timeout=30)
                print("\nDtrace Output:")
                print(stdout)
                print("\nDtrace Errors:")
                print(stderr)
                print("✅ Trace command completed")
                
                # Check if output file was created
                import os
                if os.path.exists('dtrace_output.txt'):
                    print("\nOutput file created successfully")
                    with open('dtrace_output.txt', 'r') as f:
                        print("\nFirst few lines of output:")
                        print(f.read()[:500])
                else:
                    print("\n❌ No output file was created")
                
                return True
            except subprocess.TimeoutExpired:
                print("Stopping trace collection...")
                process.terminate()
                return True
                
        else:  # Linux
            print("\nℹ️  Admin privileges required to run strace")
            print("⌨️  Please enter your system administrator password when prompted")
            print("   (Your password will not be visible as you type)\n")
            cmd = ['sudo', 'strace', '-f', '-p', str(pid), '-o', 'strace_output.log']
        
        # Run the command with a timeout
        process = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        print("✅ Trace command completed successfully")
        return True
    except subprocess.TimeoutExpired:
        print("⚠️  Trace command timed out after 30 seconds")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running trace command: {e}")
        return False
    except KeyboardInterrupt:
        print("\n⚠️  Trace command interrupted by user")
        return True
    except Exception as e:
        print(f"❌ Unexpected error in trace command: {e}")
        print(f"Error type: {type(e)}")
        import traceback
        traceback.print_exc()
        return False

def parse_trace_output() -> set:
    """Parse the dtrace/strace output to extract file paths."""
    file_paths = set()
    try:
        filename = 'dtrace_output.txt' if platform.system() == 'Darwin' else 'strace_output.log'
        print(f"Parsing {filename}...")
        
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
    except FileNotFoundError:
        print(f"{filename} not found")
    except Exception as e:
        print(f"Error parsing trace output: {e}")
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
    except subprocess.CalledProcessError as e:
        print(f"Error getting Docker images: {e.stderr}")
        return []
    except Exception as e:
        print(f"Unexpected error getting images: {e}")
        return []

def analyze_container_files(container) -> set:
    """Analyze files being used in the container, excluding node_modules"""
    print("\nAnalyzing container file usage...")
    used_files = set()
    
    try:
        # Get application source files only
        print("Getting application source files...")
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
            '-not -path "*/node_modules/*" '  # Exclude node_modules
            '-not -path "*/dist/*" '          # Exclude build artifacts
            '-not -path "*/.git/*" '          # Exclude git files
        )
        
        if app_cmd.exit_code == 0:
            app_files = app_cmd.output.decode('utf-8').split('\n')
            used_files.update(f for f in app_files if f)
        
        # Categorize files
        source_files = {f for f in used_files if f.endswith(('.js', '.jsx', '.ts', '.tsx'))}
        config_files = {f for f in used_files if f.endswith('.json')}
        style_files = {f for f in used_files if f.endswith(('.css', '.html'))}
        
        print("\nFile Usage Summary:")
        print(f"Source files: {len(source_files)}")
        print(f"Config files: {len(config_files)}")
        print(f"Style files: {len(style_files)}")
        
        if source_files:
            print("\nSource Files:")
            for f in sorted(source_files):
                print(f)
                
        if config_files:
            print("\nConfig Files:")
            for f in sorted(config_files):
                print(f)
                
        if style_files:
            print("\nStyle Files:")
            for f in sorted(style_files):
                print(f)
        
        return used_files
        
    except Exception as e:
        print(f"Error analyzing container: {e}")
        import traceback
        traceback.print_exc()
        return set()

def main():
    print("\n🔍 Docker Image Analyzer")
    print("------------------------")
    print("Note: This tool requires administrator privileges to analyze container behavior.")
    print("You can press Ctrl+C at any time to stop the analysis.")

    # Get available images
    images = get_available_images()
    if not images:
        print("No Docker images found. Please pull some images first.")
        return
    print(images)

    # Create the selection prompt with image sizes
    choices = [(f"{image} ({size})", image) for image, size in images]
    questions = [
        inquirer.List('image',
                     message="Select a Docker image to analyze",
                     choices=choices,
                     carousel=True)
    ]

    try:
        # Get user selection
        answers = inquirer.prompt(questions, theme=themes.GreenPassion())
        if not answers:
            print("\nAnalysis cancelled.")
            return

        selected_image = answers['image']
        print(f"\nAnalyzing image: {selected_image}")
        
        # Create analyzer instance
        analyzer = DockerAnalyzer()
        container = analyzer.container_manager.ensure_container_exists(selected_image)
        if not container:
            print("Failed to create/get container")
            return
            
        # Analyze files
        used_files = analyze_container_files(container)
        
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
        if 'analyzer' in locals():
            analyzer.__del__()

if __name__ == "__main__":
    main()
