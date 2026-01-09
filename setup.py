"""Setup configuration for Linux Health Security Scanner."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="linux-health",
    version="2.0.0",
    author="Linux Health Contributors",
    description="Enterprise-grade security assessment platform for Linux infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/linux_health",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/linux_health/issues",
        "Documentation": "https://github.com/yourusername/linux_health#readme",
        "Source Code": "https://github.com/yourusername/linux_health",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "linux-health=linux_health.cli:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "security",
        "scanning",
        "linux",
        "malware",
        "vulnerability",
        "compliance",
        "audit",
    ],
)
