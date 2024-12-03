import subprocess
from typing import Set, Dict, Optional
import platform
import os
import time

class FileAccessTracker:
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.dtrace_process = None
        self.accessed_files = set()
        self.os_type = platform.system()
        
    def start_tracking(self):
        """Start tracking based on OS type"""
        if self.os_type == 'Darwin':  # macOS
            return self._start_dtrace()
        elif self.os_type == 'Linux':
            return self._start_strace()
        return False
            
    def _start_dtrace(self) -> bool:
        """Start dtrace for macOS"""
        dtrace_script = '''
        syscall::open*:entry,syscall::stat*:entry
        /pid == $target/
        {
            printf("%s %s\\n", probefunc, copyinstr(arg0));
        }
        '''
        try:
            # Get container PID
            cmd = ["docker", "inspect", "-f", '{{.State.Pid}}', self.container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            pid = result.stdout.strip()
            
            # Write dtrace script
            with open('file_trace.d', 'w') as f:
                f.write(dtrace_script)
            
            # Start dtrace
            self.dtrace_process = subprocess.Popen([
                'sudo', 'dtrace', '-s', 'file_trace.d',
                '-p', pid, '-o', 'dtrace_output.txt'
            ])
            return True
        except Exception as e:
            print(f"Error starting dtrace: {e}")
            return False
            
    def _start_strace(self) -> bool:
        """Start strace for Linux"""
        try:
            cmd = ["docker", "inspect", "-f", '{{.State.Pid}}', self.container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            pid = result.stdout.strip()
            
            self.strace_process = subprocess.Popen([
                'sudo', 'strace', '-f', 
                '-e', 'trace=open,openat,stat,access',
                '-p', pid, '-o', f'strace_output.txt'
            ])
            return True
        except Exception as e:
            print(f"Error starting strace: {e}")
            return False

    def get_accessed_files(self) -> Dict[str, Set[str]]:
        """Collect results based on OS type"""
        if self.os_type == 'Darwin':
            return self._parse_dtrace_output()
        elif self.os_type == 'Linux':
            return self._parse_strace_output()
        return {'files': set()}

    def _parse_dtrace_output(self) -> Dict[str, Set[str]]:
        files = set()
        try:
            with open('dtrace_output.txt', 'r') as f:
                for line in f:
                    if 'open' in line or 'stat' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            files.add(parts[-1])
        except FileNotFoundError:
            pass
        return {'files': files}

    def _parse_strace_output(self) -> Dict[str, Set[str]]:
        files = set()
        try:
            with open('strace_output.txt', 'r') as f:
                for line in f:
                    if 'open(' in line or 'openat(' in line:
                        if '"' in line:
                            path = line.split('"')[1]
                            files.add(path)
        except FileNotFoundError:
            pass
        return {'files': files}

    def cleanup(self):
        """Cleanup tracking resources"""
        if self.dtrace_process:
            self.dtrace_process.terminate()
            try:
                os.remove('file_trace.d')
                os.remove('dtrace_output.txt')
            except OSError:
                pass
        if hasattr(self, 'strace_process') and self.strace_process:
            self.strace_process.terminate()
            try:
                os.remove('strace_output.txt')
            except OSError:
                pass
