import io
from setuptools import setup, find_packages


def parse_requirements(file):
    required = []
    with open(file) as f:
        for req in f.read().splitlines():
            if not req.strip().startswith('#'):
                required.append(req)
    return required


def read(*args, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in args:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)


requirements = parse_requirements('requirements.txt')
long_description = read('README.md', )


setup(
    name="patator",
    version="0.7-beta",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 3',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Topic :: Utilities',
        'Topic :: Security',
    ],


    # metadata for upload to PyPI
    author="Sebastien Macke",
    author_email="pastor@hsc.fr",
    description="A multi-threaded brute-force tool",
    long_description=long_description,
    license="GPLv2",
    keywords="pentest brute force penetration test security",
    url="https://github.com/lanjelot/patator",
    entry_points={
        'console_scripts': [
            'ftp_login=patator.patator:main',
            'ssh_login=patator.patator:main',
            'telnet_login=patator.patator:main',
            'smtp_login=patator.patator:main',
            'smtp_vrfy=patator.patator:main',
            'smtp_rcpt=patator.patator:main',
            'finger_lookup=patator.patator:main',
            'http_fuzz=patator.patator:main',
            'ajp_fuzz=patator.patator:main',
            'pop_login=patator.patator:main',
            'pop_passd=patator.patator:main',
            'imap_login=patator.patator:main',
            'ldap_login=patator.patator:main',
            'smb_login=patator.patator:main',
            'smb_lookupsid=patator.patator:main',
            'rlogin_login=patator.patator:main',
            'vmauthd_login=patator.patator:main',
            'mssql_login=patator.patator:main',
            'oracle_login=patator.patator:main',
            'mysql_login=patator.patator:main',
            'mysql_query=patator.patator:main',
            'rdp_login=patator.patator:main',
            'pgsql_login=patator.patator:main',
            'vnc_login=patator.patator:main',
            'dns_forward=patator.patator:main',
            'dns_reverse=patator.patator:main',
            'snmp_login=patator.patator:main',
            'ike_enum=patator.patator:main',
            'unzip_pass=patator.patator:main',
            'keystore_pass=patator.patator:main',
            'sqlcipher_pass=patator.patator:main',
            'umbraco_crack=patator.patator:main',
            'tcp_fuzz=patator.patator:main',
            'dummy_test=patator.patator:main',
        ],
    },
)
