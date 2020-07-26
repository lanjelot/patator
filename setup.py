from setuptools import setup, find_packages

def parse_requirements(file):
    required = []
    with open(file) as f:
        for req in f.read().splitlines():
            if not req.strip().startswith('#'):
                required.append(req)
    return required

requirements = parse_requirements('requirements.txt')
long_description = "Patator was written out of frustration from using Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE scripts for password guessing attacks. I opted for a different approach in order to not create yet another brute-forcing tool and avoid repeating the same shortcomings. Patator is a multi-threaded tool written in Python, that strives to be more reliable and flexible than his fellow predecessors."

setup(
    name="patator",
    version="0.9",
    description="multi-purpose brute-forcer",
    long_description=long_description,
    url="https://github.com/lanjelot/patator",
    author="Sebastien Macke",
    author_email="patator@hsc.fr",
    license="GPLv2",

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

    keywords="pentest brute force password attack",
    packages=find_packages(),
    install_requires=requirements,

    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, <4',

    scripts=['patator.py'],
)
