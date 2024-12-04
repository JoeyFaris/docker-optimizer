from typing import List, Dict, Optional, Set, Tuple
import os

class FilesystemAnalyzer:
    def __init__(self, container):
        self.container = container

    def get_all_files_with_size(self) -> List[Tuple[str, int]]:
        """Get list of all files in container with their sizes"""
        try:
            exec_command = self.container.exec_run(r'find / -type f -exec ls -l {} \;')
            if exec_command.exit_code != 0:
                return []
            
            files_with_size = []
            for line in exec_command.output.decode('utf-8').split('\n'):
                if line:
                    try:
                        parts = line.split()
                        if len(parts) >= 5:
                            size = int(parts[4])
                            path = ' '.join(parts[8:])
                            files_with_size.append((path, size))
                    except (IndexError, ValueError):
                        continue
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
            '/var/lock', '/var/lib/dpkg', '/var/cache', '/var/log'
        }
        return any(path.startswith(p) for p in system_paths) 