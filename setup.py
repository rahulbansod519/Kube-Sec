from setuptools import setup, find_packages

setup(
    name="kube-sec",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "click",
        "kubernetes",
        "colorama",
        "python-dotenv",
        "schedule",
    
    ],
    entry_points={
        "console_scripts": [
            "kube-sec=kube_secure.cli:cli",
        ],
    },

    python_requires=">=3.6",
)
