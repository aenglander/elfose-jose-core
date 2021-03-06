from setuptools import setup

setup(
    name="elfose-core-pycryptodome",
    version="0.1",
    python_requires=">= 3.6",
    package_dir={"": "src"},
    zip_safe=False,
    test_suite="tests",
    install_requires=["pycryptodome~=3.9"],
)
