# Docker Documentation

Complete guide for building, running, and deploying Linux Health Scanner with Docker.

## Quick Start

### Build Image

```bash
# Build image from Dockerfile
docker build -t linux-health .

# Build with specific tag and version
docker build -t linux-health:1.0.0 .

# Build with multiple tags
docker build -t linux-health:latest -t linux-health:1.0.0 .
```

### Run Scan

```bash
# Basic scan
docker run --rm linux-health 192.168.1.100 username password

# Save report to local file
docker run --rm -v "$(pwd):/reports" linux-health \
  192.168.1.100 username password \
  --format md --output /reports/scan.md

# Interactive password prompt
docker run -it --rm linux-health 192.168.1.100 username - --ask-password
```

## Docker Image Details

### Base Image
- **Python 3.11-slim**: Lightweight Debian-based image
- **Size**: ~200MB (with dependencies: ~250MB)
- **Includes**: Python runtime, pip, SSH client, curl, wget

### Image Composition

```dockerfile
FROM python:3.11-slim
  ↓
Install OpenSSH client (for SSH connections)
  ↓
Install Python dependencies (paramiko)
  ↓
Copy application code
  ↓
Set entrypoint: python -m linux_health
```

### Build Details

```bash
# Layer 1: Base Python image
# Layer 2: System packages
# Layer 3: Python dependencies
# Layer 4: Application code
# Layer 5: Metadata
```

Check layer sizes:

```bash
docker history linux-health:latest
```

## Docker Compose

### Basic Setup

```yaml
version: '3.8'

services:
  linux-health:
    build: .
    image: linux-health:latest
    container_name: linux-health
    environment:
      - PYTHONUNBUFFERED=1
    volumes:
      - ./reports:/app/reports
```

### Running with Compose

```bash
# Run scan
docker-compose run --rm linux-health 192.168.1.100 username password

# Save to reports directory
docker-compose run --rm linux-health \
  192.168.1.100 username password \
  --format md --output /app/reports/scan.md

# Interactive
docker-compose run -it --rm linux-health 192.168.1.100 username -
```

## Volume Mounts

### Save Reports Locally

```bash
# Unix/Linux/Mac
docker run --rm -v "$(pwd)/reports:/reports" linux-health \
  host user pass --format md --output /reports/report.md

# Windows PowerShell
docker run --rm -v "${PWD}/reports:/reports" linux-health `
  host user pass --format md --output /reports/report.md

# Windows cmd
docker run --rm -v "%cd%\reports:/reports" linux-health ^
  host user pass --format md --output /reports/report.md
```

### Multiple Directories

```bash
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  -v "$(pwd)/config:/config" \
  -v "/etc/hosts:/etc/hosts:ro" \
  linux-health host user pass
```

## Environment Variables

### Available Variables

```bash
# Python environment
PYTHONUNBUFFERED=1     # Show output in real-time
PYTHONIOENCODING=utf-8 # UTF-8 encoding

# Network
TIMEOUT=30             # SSH timeout in seconds
PORT=2222              # SSH port
```

### Using Environment Variables

```bash
docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e TIMEOUT=30 \
  linux-health 192.168.1.100 user pass --port 2222
```

## Networking

### Host Network Mode

```bash
# Use host network (Linux only)
docker run --rm --network host linux-health \
  localhost user pass
```

### Custom Networks

```bash
# Create custom network
docker network create linux-health-net

# Run scanner on network
docker run --rm --network linux-health-net \
  --name scanner \
  linux-health 192.168.1.100 user pass

# Run target server on network
docker run --rm --network linux-health-net \
  --name target \
  ubuntu:22.04
```

## Port Scanning

### Port Specification in Docker

```bash
# Scan custom ports
docker run --rm linux-health \
  192.168.1.100 user pass \
  --scan-ports 22,80,443,8080,9000

# Scan range
docker run --rm linux-health \
  192.168.1.100 user pass \
  --scan-ports 22,80,443,3306-3310,5432
```

## Credentials Management

### Methods to Handle Credentials

#### 1. Command-Line Argument (Simple)
```bash
docker run --rm linux-health host user password
# WARNING: Visible in process list
```

#### 2. Interactive Prompt (Secure)
```bash
docker run -it --rm linux-health host user - --ask-password
# Prompt: Enter password: ****
```

#### 3. Environment Variable (Better)
```bash
docker run --rm \
  -e PASSWORD="your-password" \
  linux-health host user $PASSWORD
# Still visible in environment, use with caution
```

#### 4. Secrets File (Best - Docker Swarm/Kubernetes)
```bash
# Using Docker Swarm
echo "password" | docker secret create ssh_password -
docker service create \
  --secret ssh_password \
  linux-health host user $(cat /run/secrets/ssh_password)

# Using Kubernetes
kubectl create secret generic ssh-creds \
  --from-literal=password=mysecretpass
```

#### 5. Docker BuildKit Secrets (Build-time)
```bash
docker build \
  --secret ssh_pass \
  -t linux-health .

# In Dockerfile:
RUN --mount=type=secret,id=ssh_pass \
  cat /run/secrets/ssh_pass > /tmp/password
```

## Continuous Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, schedule]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Build scanner image
        run: docker build -t linux-health .
      
      - name: Run scan
        run: |
          docker run --rm linux-health \
            192.168.1.100 \
            ${{ secrets.SCAN_USER }} \
            ${{ secrets.SCAN_PASS }} \
            --format md --output scan_report.md
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: scan_report.md
```

### GitLab CI

```yaml
scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t linux-health .
    - docker run --rm linux-health 192.168.1.100 $CI_USER $CI_PASS --format md --output scan.md
  artifacts:
    paths:
      - scan.md
```

## Image Registry

### Docker Hub

```bash
# Tag for Docker Hub
docker tag linux-health:latest username/linux-health:latest
docker tag linux-health:latest username/linux-health:1.0.0

# Push to registry
docker login
docker push username/linux-health:latest
docker push username/linux-health:1.0.0

# Pull from registry
docker pull username/linux-health:latest
```

### GitHub Container Registry (GHCR)

```bash
# Login
echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin

# Tag
docker tag linux-health:latest ghcr.io/${{ github.repository }}/linux-health:latest

# Push
docker push ghcr.io/${{ github.repository }}/linux-health:latest
```

## Optimization

### Reduce Image Size

```bash
# Current size
docker images linux-health

# Build with multi-stage for smaller image
# FROM python:3.11-slim as base
# ... build stage ...
# FROM python:3.11-slim
# COPY --from=base /app /app
```

### Build Cache

```bash
# Use cache for faster builds
docker build -t linux-health:latest .

# Build without cache
docker build --no-cache -t linux-health:latest .

# Inspect cache
docker builder prune --verbose
```

## Debugging

### Interactive Shell

```bash
# Run shell instead of main command
docker run -it --rm linux-health /bin/bash

# From running container
docker exec -it <container-id> /bin/bash
```

### View Container Logs

```bash
# Stream logs
docker logs -f <container-id>

# Last 100 lines
docker logs --tail 100 <container-id>

# With timestamps
docker logs --timestamps <container-id>
```

### Inspect Container

```bash
# View container details
docker inspect <container-id>

# View processes
docker top <container-id>

# View resource usage
docker stats <container-id>
```

## Security Best Practices

### Image Scanning

```bash
# Scan with Trivy
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image linux-health:latest

# Scan for critical vulnerabilities
trivy image --severity CRITICAL linux-health:latest
```

### Run as Non-Root

```dockerfile
# In Dockerfile
RUN useradd -m -u 1000 scanner
USER scanner

# Or in docker run
docker run --rm --user 1000:1000 linux-health host user pass
```

### Read-Only Filesystem

```bash
docker run --rm --read-only linux-health \
  --tmpfs /tmp \
  host user pass
```

### Resource Limits

```bash
docker run --rm \
  --memory 512m \
  --cpus 1 \
  --pids-limit 100 \
  linux-health host user pass
```

## Troubleshooting

### Image Won't Build

```bash
# Check build process
docker build -t linux-health . --progress=plain

# Check Dockerfile syntax
docker build --check -f Dockerfile .

# View layer history
docker history linux-health
```

### Container Exits Immediately

```bash
# Check logs
docker logs <container-id>

# Run with keep-alive
docker run -it --rm linux-health bash

# Check entrypoint
docker inspect linux-health | grep -A 5 Entrypoint
```

### SSH Connection Fails in Container

```bash
# Verify SSH client is installed
docker run --rm linux-health which ssh

# Check SSH version
docker run --rm linux-health ssh -V

# Test connectivity
docker run --rm linux-health ssh -vvv host
```

### Volume Mount Issues

```bash
# Check volume mount
docker run --rm -v "$(pwd):/reports" linux-health \
  ls -la /reports

# Fix permissions
docker run --rm -v "$(pwd):/reports" linux-health \
  chmod 777 /reports

# Use :z flag for SELinux
docker run --rm -v "$(pwd):/reports:z" linux-health ...
```

## Deployment Scenarios

### Single Host Scan

```bash
docker run --rm linux-health \
  192.168.1.100 admin password \
  --format md --output report.md
```

### Batch Scanning Multiple Hosts

```bash
#!/bin/bash
for host in 192.168.1.{100..110}; do
  echo "Scanning $host..."
  docker run --rm -v "$(pwd)/reports:/reports" linux-health \
    $host admin password \
    --format md --output "/reports/report_${host}.md"
done
```

### Kubernetes Deployment

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: linux-health-scan
spec:
  template:
    spec:
      containers:
      - name: scanner
        image: linux-health:latest
        args:
          - "192.168.1.100"
          - "username"
          - "$(SSH_PASSWORD)"
        env:
        - name: SSH_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ssh-credentials
              key: password
        volumeMounts:
        - name: reports
          mountPath: /reports
      volumes:
      - name: reports
        persistentVolumeClaim:
          claimName: reports-pvc
      restartPolicy: Never
```

---

For more information, see the main README.md or DEVELOPMENT.md.
