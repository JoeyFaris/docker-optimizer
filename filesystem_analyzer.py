from typing import List, Dict, Optional, Set, Tuple
import os
from dynamic_analyzer import DynamicAnalyzer

class FilesystemAnalyzer:
    def __init__(self, container):
        self.container = container

    def get_all_files_with_size(self) -> List[Tuple[str, int]]:
        """Get list of all files in container with their sizes"""
        try:
            # First ensure we have the tools we need
            self.container.exec_run('which find || apt-get update && apt-get install -y findutils')
            
            # Use a more reliable command with proper escaping
            cmd = r"""find / -type f -exec sh -c 'echo $(du -ab "{}" | cut -f1) "{}"' \;"""
            exec_command = self.container.exec_run(['sh', '-c', cmd])
            
            if exec_command.exit_code != 0:
                print(f"Error running find command: {exec_command.output.decode('utf-8')}")
                return []
            
            files_with_size = []
            for line in exec_command.output.decode('utf-8').split('\n'):
                if line:
                    try:
                        # Format: size path
                        parts = line.strip().split(maxsplit=1)
                        if len(parts) == 2:
                            size = int(parts[0])
                            path = parts[1].strip('"')  # Remove quotes
                            files_with_size.append((path, size))
                    except (IndexError, ValueError) as e:
                        continue
            
            print(f"Debug: Found {len(files_with_size)} total files with sizes")
            total_size = sum(size for _, size in files_with_size)
            print(f"Debug: Total size of all files: {total_size} bytes")
            
            return files_with_size
        except Exception as e:
            print(f"Error getting files with sizes: {e}")
            return []

    def get_lsof_files(self) -> Set[str]:
        """Get list of files currently opened by processes"""
        try:
            exec_command = self.container.exec_run('lsof -F n')
            if exec_command.exit_code != 0:
                return set()
            
            files = set()
            for line in exec_command.output.decode('utf-8').split('\n'):
                if line.startswith('n/'):
                    files.add(line[1:])  # Remove 'n' prefix
            return files
        except Exception as e:
            print(f"Error getting lsof files: {e}")
            return set()

    def get_proc_files(self) -> Set[str]:
        """Get list of files from /proc filesystem"""
        try:
            exec_command = self.container.exec_run('find /proc/*/fd -type l -ls')
            if exec_command.exit_code != 0:
                return set()
            
            files = set()
            for line in exec_command.output.decode('utf-8').split('\n'):
                if ' -> ' in line:
                    target = line.split(' -> ')[1].strip()
                    if target.startswith('/'):
                        files.add(target)
            return files
        except Exception as e:
            print(f"Error getting proc files: {e}")
            return set()

    def is_system_path(self, path: str) -> bool:
        """Check if a path is a system path that should be excluded from analysis"""
        system_paths = {
            '/proc', '/sys', '/dev', '/tmp', '/run', '/var/run',
            '/var/lock', '/var/cache', '/var/log'
        }
        # Remove /var/lib/dpkg from system paths to include package files
        return any(path.startswith(p) for p in system_paths)

    def get_all_used_files(self) -> Set[str]:
        """Get comprehensive list of used files"""
        used_files = set()
        
        try:
            # Install necessary tools
            self.container.exec_run('apt-get update && apt-get install -y lsof')
            
            # Static analysis
            lsof_files = self.get_lsof_files()
            proc_files = self.get_proc_files()
            
            print(f"Debug: Found {len(lsof_files)} files from lsof")
            print(f"Debug: Found {len(proc_files)} files from proc")
            
            used_files.update(lsof_files)
            used_files.update(proc_files)
            
            # Add some common used files that might be missed
            common_used = {
                '/etc/passwd', '/etc/group', '/etc/hosts',
                '/etc/resolv.conf', '/etc/ssl/certs',
                '/usr/lib', '/lib', '/bin', '/sbin'
            }
            used_files.update(common_used)
            
            return used_files
        except Exception as e:
            print(f"Error getting used files: {e}")
            return set()