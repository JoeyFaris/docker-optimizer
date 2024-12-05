class SecurityScanner:
    def __init__(self, client, container):
        self.client = client
        self.container = container

    def scan_security(self, image_name: str) -> dict:
        """Basic security scan of the image"""
        results = {
            'root_processes': [],
            'exposed_ports': [],
            'environment_vars': [],
            'privileged_capabilities': []
        }
        
        try:
            image = self.client.images.get(image_name)
            config = image.attrs['Config']
            
            # Check exposed ports
            if config.get('ExposedPorts'):
                # Convert port mappings to more readable format
                ports = []
                for port in config['ExposedPorts'].keys():
                    # Split port/protocol (e.g., "80/tcp" -> "80 (TCP)")
                    port_num, proto = port.split('/')
                    ports.append(f"{port_num} ({proto.upper()})")
                results['exposed_ports'] = ports
                
            # Check environment variables
            if config.get('Env'):
                results['environment_vars'] = [
                    env for env in config['Env'] 
                    if not any(secret in env.lower() 
                              for secret in ['password', 'key', 'token', 'secret'])
                ]
                
            # Check for root processes
            if self.container:
                ps_cmd = self.container.exec_run('ps aux')
                if ps_cmd.exit_code == 0:
                    processes = ps_cmd.output.decode('utf-8').split('\n')
                    results['root_processes'] = [
                        p for p in processes if p.startswith('root')
                    ]
                    
            return results
        except Exception as e:
            return {'error': str(e)} 