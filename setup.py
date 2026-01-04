from pathlib import Path
from setuptools import setup, find_packages
import re

HERE = Path(__file__).parent

long_description = (HERE / "README.md").read_text(encoding="utf-8")
init_text = (HERE / "maxhttp" / "_version.py").read_text(encoding="utf-8")
_version_match = re.search(r'^__version__\s*=\s*[\'\"]([^\'\"]+)[\'\"]', init_text, re.M)
version = _version_match.group(1) if _version_match else "0.0.0"

setup(
    name="maxhttp",
    version=version,
    description="Blazing-fast Python HTTP client offering unified sync/async APIs with smart pooling.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Shayan Heidari",
    packages=find_packages(include=["maxhttp", "maxhttp.*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=["h11pro", "wsproto"],
    extras_require={
        "h2": ["h2>=4.1.0"],
    },
    license="GNU General Public License v3 (GPLv3)",
    license_files=["LICENSE"],
    url="https://github.com/shayanheidari01/maxhttp",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
    ],
)
