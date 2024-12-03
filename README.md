# Docker Image Analyzer

A powerful tool for analyzing Docker images and containers to identify optimization opportunities and security concerns.

## Features

- 🔍 Layer Analysis: Examine Docker image layers and their sizes
- 📁 File System Analysis: Identify unused files and potential bloat
- 🔒 Security Scanning: Check for exposed ports, root processes, and environment variables
- 📊 Resource Usage: Monitor container resource utilization
- 🔄 File Access Tracking: Track file access patterns during runtime

## Prerequisites

- Python 3.12 or higher
- Docker installed and running
- macOS or Linux operating system

## Installation

1. Clone the repository:
git clone <your-repo-url>
cd docker-trim

2. Create and activate a virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
pip install -r requirements.txt

## Usage

1. Run the analyzer:
python optimizer.py

2. Select a Docker image from the interactive menu
3. Wait for the analysis to complete
4. Review the results

## Building with Docker

1. Build the image:
docker build -t docker-analyzer .

2. Run the container:
docker run -v /var/run/docker.sock:/var/run/docker.sock docker-analyzer

## Output Example

🚀 Starting Docker Image Analysis
================================

[1/5] Analyzing image layers
[2/5] Analyzing filesystem
[3/5] Analyzing file usage
[4/5] Performing security scan
[5/5] Tracking file access patterns

✨ Analysis completed in 12.9 seconds

📊 Analysis Results
=================
• Total layers: 11
• Total size: 2.06GB
• Unused files: 30742
• Exposed ports: 1
• Root processes: 2

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Docker SDK for Python
- Rich library for terminal formatting
- Inquirer for interactive CLI