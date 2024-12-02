import docker
from typing import Optional

class ContainerManager:
    def __init__(self, client):
        self.client = client
        self.active_container = None

    def ensure_container_exists(self, image_name: str) -> Optional[docker.models.containers.Container]:
        """Creates a container if it doesn't exist, or returns existing one"""
        print(f"Ensuring container exists for image: {image_name}")
        
        try:
            # First, check for existing running containers with this image
            containers = self.client.containers.list(
                filters={'ancestor': image_name, 'status': 'running'}
            )
            
            if containers:
                print(f"Found existing running container: {containers[0].id[:12]}")
                self.active_container = containers[0]
                return containers[0]
            
            # If no running container found, create a new one
            print("Creating new container...")
            container = self.client.containers.create(
                image_name,
                command="tail -f /dev/null",  # Keep container running
                ports={'3000/tcp': 3000},
                detach=True,
                tty=True,
                stdin_open=True
            )
            container.start()
            self.active_container = container
            
            # Verify container is running
            container.reload()
            print(f"Container status: {container.status}")
            
            if container.status != 'running':
                print("❌ Container failed to start properly")
                return None
            
            print(f"Container created and started: {container.id[:12]}")
            return container
            
        except docker.errors.ImageNotFound:
            print(f"Error: Image '{image_name}' not found locally")
            return None
        except docker.errors.APIError as e:
            print(f"Error creating container: {e}")
            return None
        except Exception as e:
            print(f"Error testing container: {e}")
            return None

    def cleanup(self):
        """Cleanup the active container"""
        if self.active_container:
            # Only cleanup if we created this container
            if not self.active_container.name in ['eager_ganguly', 'boring_gould', 'bold_knuth']:
                print("Cleaning up container...")
                try:
                    self.active_container.stop()
                    self.active_container.remove()
                    print("Container cleaned up successfully")
                except docker.errors.APIError as e:
                    print(f"Error cleaning up container: {e}")
            self.active_container = None
