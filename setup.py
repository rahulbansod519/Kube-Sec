from setuptools import setup, find_packages

setup(
    name="kube-sec",
    version="0.1.0",
    description="A Kubernetes Security Hardening CLI with built-in and custom rule checks",
    author="Rahul Bansod",
    author_email="rahulbansod519@email.com",
    url="https://github.com/rahulbansod519/Kube-Sec.git", 
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0",
        "kubernetes>=26.1.0",
        "colorama",
        "python-dotenv",
        "schedule",
        "keyring",
        "tenacity",
        "pyyaml",
        "jmespath",
        "tabulate"
    ],
    entry_points={
        "console_scripts": [
            "kube-sec=kube_secure.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Environment :: Console"
    ],
    python_requires=">=3.8",
)
