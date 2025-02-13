from typing import Dict, List, Optional
import docker
from concurrent.futures import ThreadPoolExecutor

class ImageAnalyzer:
    def __init__(self, client: docker.DockerClient):
        self.client = client

    def analyze_layers(self, image_name: str) -> Optional[Dict]:
        """Analyze Docker image layers and their sizes"""
        try:
            image = self.client.images.get(image_name)
            with ThreadPoolExecutor() as executor:
                layer_futures = [
                    executor.submit(self._analyze_layer, layer)
                    for layer in image.history()
                ]
                layers = [f.result() for f in layer_futures if f.result()['Size'] > 0]
            
            total_size = sum(layer['raw_size'] for layer in layers)
            
            return {
                'layers': layers,
                'total_size': self._format_size(total_size),
                'total_layers': len(layers),
                'base_image': image.attrs['Config'].get('Image', 'unknown'),
                'created': image.attrs['Created'],
                'architecture': image.attrs['Architecture']
            }
        except docker.errors.ImageNotFound:
            print(f"Image {image_name} not found")
            return None
        except Exception as e:
            print(f"Error analyzing image: {e}")
            return None

    def _format_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f}TB"

    def _analyze_layer(self, layer):
        if layer['Size'] > 0:  # Skip empty layers
            return {
                'created_by': layer.get('CreatedBy', 'unknown'),
                'size': self._format_size(layer['Size']),
                'raw_size': layer['Size']
            }
        return None
