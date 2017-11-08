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
            'ftp_login=patator:main',
            'ssh_login=patator:main',
            'telnet_login=patator:main',
            'smtp_login=patator:main',
            'smtp_vrfy=patator:main',
            'smtp_rcpt=patator:main',
            'finger_lookup=patator:main',
            'http_fuzz=patator:main',
            'ajp_fuzz=patator:main',
            'pop_login=patator:main',
            'pop_passd=patator:main',
            'imap_login=patator:main',
            'ldap_login=patator:main',
            'smb_login=patator:main',
            'smb_lookupsid=patator:main',
            'rlogin_login=patator:main',
            'vmauthd_login=patator:main',
            'mssql_login=patator:main',
            'oracle_login=patator:main',
            'mysql_login=patator:main',
            'mysql_query=patator:main',
            'rdp_login=patator:main',
            'pgsql_login=patator:main',
            'vnc_login=patator:main',
            'dns_forward=patator:main',
            'dns_reverse=patator:main',
            'snmp_login=patator:main',
            'ike_enum=patator:main',
            'unzip_pass=patator:main',
            'keystore_pass=patator:main',
            'sqlcipher_pass=patator:main',
            'umbraco_crack=patator:main',
            'tcp_fuzz=patator:main',
            'dummy_test=patator:main',
        ],
    },
)
