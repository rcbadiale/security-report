import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="security_report",
    version="1.0.0",
    author="Rafael Badiale",
    author_email="rcbadiale@gmail.com",
    description=(
        "Proccess SAST Security Reports from multiple JSON files into one."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rcbadiale/security-report",
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3'
    ],
    packages=setuptools.find_packages(include=["security_report"]),
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'security-report=security_report.main:cli'
        ]
    }
)
