from pathlib import Path
from setuptools import setup, find_packages
import re

HERE = Path(__file__).parent

long_description = (HERE / "README.md").read_text(encoding="utf-8")
init_text = (HERE / "fasthttp" / "__init__.py").read_text(encoding="utf-8")
_version_match = re.search(r'^__version__\s*=\s*[\'\"]([^\'\"]+)[\'\"]', init_text, re.M)
version = _version_match.group(1) if _version_match else "0.0.0"

setup(
    name="pyfasthttp",
    version=version,
    description="Lightweight sync/async HTTP client with pooling built on h11.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Shayan Heidari",
    packages=find_packages(include=["fasthttp", "fasthttp.*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=["h11>=0.14.0"],
    license="GNU General Public License v3 (GPLv3)",
    license_files=["LICENSE"],
    url="https://github.com/shayanheidari01/fasthttp",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
    ],
)
