from setuptools import setup, find_packages

setup(
    name="vxdf-validate",
    version="1.0.0",
    description="VXDF Validation Engine - Validate and document security vulnerabilities",
    author="Mihir Shah",
    author_email="mihir@mihirshah.tech",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "flask>=3.1.0",
        "flask-cors>=4.0.0",
        "flask-sqlalchemy>=3.1.1",
        "gunicorn>=23.0.0",
        "psycopg2-binary>=2.9.10",
        "pydantic>=2.11.4",
        "requests>=2.32.3",
        "beautifulsoup4>=4.13.4",
        "cryptography>=44.0.3",
    ],
    entry_points={
        'console_scripts': [
            'vxdf-validate=vxdf_validate.cli:cli',
        ],
    },
    python_requires='>=3.9',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
) 