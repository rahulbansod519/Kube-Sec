from pathlib import Path

from setuptools import find_packages, setup


BASE_DIR = Path(__file__).parent
README = (BASE_DIR / "README.md").read_text(encoding="utf-8")
VERSION = {}
exec((BASE_DIR / "kube_secure" / "__init__.py").read_text(encoding="utf-8"), VERSION)


setup(
    name="kube-sec",
    version=VERSION["__version__"],
    description="A Kubernetes security scanning CLI for misconfiguration detection and fast reporting",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Rahul Bansod",
    author_email="rahulbansod519@email.com",
    url="https://github.com/rahulbansod519/Kube-Sec",
    project_urls={
        "Documentation": "https://github.com/rahulbansod519/Kube-Sec/tree/main/kube-sec-docs",
        "Issues": "https://github.com/rahulbansod519/Kube-Sec/issues",
        "Source": "https://github.com/rahulbansod519/Kube-Sec",
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0",
        "colorama",
        "jmespath",
        "keyring",
        "kubernetes>=26.1.0",
        "pyyaml",
        "schedule",
        "tabulate",
        "tenacity",
    ],
    entry_points={
        "console_scripts": [
            "kube-sec=kube_secure.cli:cli",
        ],
    },
    keywords=["kubernetes", "security", "devsecops", "rbac", "scanner", "cli"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
)
