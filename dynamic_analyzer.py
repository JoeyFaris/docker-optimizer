import time
from typing import Set

class DynamicAnalyzer:
    def __init__(self, container):
        self.container = container
        self.accessed_files = set()
        
    def analyze(self) -> Set[str]:
        """Perform comprehensive dynamic analysis"""
        # Track startup files
        startup_files = self._track_startup()
        
        # Track runtime files with different scenarios
        runtime_files = self._track_runtime_scenarios()
        
        # Track shutdown files
        shutdown_files = self._track_shutdown()
        
        return startup_files | runtime_files | shutdown_files
        
    def _track_startup(self) -> Set[str]:
        """Track files accessed during container startup"""
        accessed = set()
        
        # Stop current container
        self.container.stop()
        
        # Start with tracing enabled
        self.container.start()
        time.sleep(5)  # Allow startup to complete
        
        # Collect startup files
        exec_result = self.container.exec_run('cat /proc/*/maps')
        if exec_result.exit_code == 0:
            for line in exec_result.output.decode().split('\n'):
                if line.startswith('/'):
                    accessed.add(line.split()[5])
                    
        return accessed
        
    def _track_runtime_scenarios(self) -> Set[str]:
        """Track files during different runtime scenarios"""
        accessed = set()
        
        # Common runtime scenarios
        scenarios = [
            self._exercise_network_activity,
            self._exercise_filesystem_operations,
            self._exercise_process_creation,
            self._exercise_dynamic_loading
        ]
        
        for scenario in scenarios:
            accessed.update(scenario())
            
        return accessed
        
    def _exercise_dynamic_loading(self) -> Set[str]:
        """Track dynamically loaded libraries and plugins"""
        accessed = set()
        
        # Monitor library loading
        exec_result = self.container.exec_run(
            'strace -f -e trace=open,openat -p 1 2>&1',
            privileged=True
        )
        
        # Trigger some activity
        self.container.exec_run('ldconfig')
        time.sleep(2)
        
        # Parse results
        if exec_result.exit_code == 0:
            for line in exec_result.output.decode().split('\n'):
                if 'open(' in line and '.so' in line:
                    path = line.split('"')[1]
                    accessed.add(path)
                    
        return accessed
