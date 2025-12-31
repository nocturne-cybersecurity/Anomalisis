from setuptools import setup, find_packages
import pathlib

# Leer el contenido de README.md
here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

# Obtener las dependencias del archivo requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="anomalisis",
    version="0.1.0",
    description="Herramienta avanzada de análisis de red y escaneo de puertos",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tu-usuario/anomalisis",
    author="Tu Nombre",
    author_email="tu@email.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="security, network, scanner, nmap, pentesting",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8, <4",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "anomalisis=start:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/tu-usuario/anomalisis/issues",
        "Source": "https://github.com/tu-usuario/anomalisis/",
    },
)
