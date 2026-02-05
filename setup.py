from setuptools import setup, find_packages

setup(
    name="sentinel-x",
    version="0.1.0",
    description="Autonomous AI incident commander for cybersecurity investigation",
    author="Sentinel-X Team",
    packages=find_packages(),
    install_requires=[
        "openai>=1.0.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "requests>=2.31.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "sentinel-x=sentinel_x.main:main",
        ],
    },
)
