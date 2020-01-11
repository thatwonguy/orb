=================================================================== 

![orb](https://orb.03c8.net/orb/orb.png)

----------

Orb: massive footprinting tool - 2016/2020 - by psy (https://03c8.net)

========================

  Orb - is a massive footprinting tool.

  It will use passive/active -automated- methods to provides you real information about
  a target. You only need to set a 'concept' to start to gather information. 

  Orb uses this methods:

     + Passive:
          - crawlering on search engines for public information (deep web included)
          - searching for registered domains
          - extracting whois info (owners, dates)
          - discovering subdomains
          - searching for machines running services
          - searching for DNS records (A, NS, MX, TXT)
          - extracting CVE and CVS records (vulnerabilities)

     + Active:
          - scanning for open ports (tcp/udp)(1-65535)
          - fingerprinting banners (states, vendors, OS, versions, CPE)

  After this tasks... Orb will provide you some fancy reports.


### License

  Orb is free software, and may be redistributed under [GPL v3].


### Installing Orb:

  Orb runs on many platforms.  It requires Python (3.x.y) and the following libraries:

       python3-whois - Python module for retrieving WHOIS information - Python 3
       whois (0.9.5) - Retrieve and parse whois data for IPv4 and IPv6 addresses.
       python3-nmap - Python3 interface to the Nmap port scanner
       nmap (0.0.1) - Map numbers from one range to another
       python3-requests - elegant and simple HTTP library for Python3, built for human beings
       requests (2.22.0) - Python HTTP for Humans.
       wikipedia (1.4.0) - Wikipedia API for Python

  On Debian-based systems (ex: Ubuntu), run: 

       sudo apt-get install python3-whois python3-nmap python3-requests && sudo pip3 install whois nmap requests wikipedia

  Or:

       sudo apt-get install python3-whois pythons3-nmap python3-requests && pip3 install whois==0.9.5 nmap==0.0.1 requests==2.22.0 wikipedia==1.4.0 --user

  Source libs:

       * Python: https://www.python.org/downloads/
       * Pypi-whois: https://pypi.python.org/pypi/whois
       * Pydnspython: https://pypi.python.org/pypi/dnspython
       * python-nmap: https://pypi.python.org/pypi/python-nmap
       * python-requests: https://pypi.org/project/requests/
       * python-wikipedia: https://pypi.org/project/wikipedia/

### Examples

  You can use:

    python3 orb --update
    python3 orb --check-tor
    python3 orb --gui (for Web interface)

  Or:

    python3 orb --spell='target'

  Ex (massive):

    python3 orb --spell='target' --ext='.com,.net,.org' --sa

## Options and features:

```
 ./orb --help

Usage: Orb.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         active verbose on requests
  --check-tor           check to see if Tor is used properly
  --update              check for latest stable version
  --spell=TARGET        start complete footprinting on this target
  --gui                 run GUI (Orb Web Interface)

  *Methods*:
    These options can be used to set some footprinting interaction
    restrictions with target(s). You only can set one:

    --passive           use only -passive- methods
    --active            use only -active- methods

  *Search Engines*:
    These options can be used to specify which search engines use to
    extract information:

    --se=ENGINE         set search engine (default: Yahoo)
    --se-ext=ENGINELOC  set location for search engine (ex: 'fr')
    --sa                search massively using all search engines

  *Public*:
    Orb will search for interesting public records. You can choose
    multiple:

    --no-public         disable search for public records
    --no-deep           disable deep web records
    --no-social         disable social records
    --social-f=SOCIALF  set a list of social sources from file
    --no-news           disable news records
    --news-f=NEWSF      set a list of news sources from file

  *Domains*:
    Orb will search on different databases for registered domains using
    IANA supported by default. You only can set one:

    --ext=EXT           set extensions manually (ex: --ext='.com,.net,.es')
    --ext-f=EXTFILE     set a list of extensions from file

  *Whois*:
    Orb will search on 'Whois' records for registrant information:

    --no-whois          disable extract whois information

  *Subdomains*:
    Orb will try to discover info about subdomains:

    --no-subs           disable try to discover subdomains

  *DNS*:
    Orb will try to discover info about DNS records and machines running
    them. You can choose multiple:

    --no-dns            disable try to discover DNS records
    --resolver=RESOLV   specify custom DNS servers (ex: '8.8.8.8,8.8.8.4')

  *Port Scanning*:
    These options can be used to specify how to perfom port scanning
    tasks. You can choose multiple:

    --no-scanner        disable scanner
    --no-scan-dns       disable scan DNS machines
    --no-scan-ns        disable scan NS records
    --no-scan-mx        disable scan MX records
    --scan-tcp          set scanning protocol to only TCP (default TCP+UDP)
    --scan-ports=PORTS  set range of ports to scan (default 1-65535)
    --show-filtered     show 'filtered' ports on results

  *Banner grabbing*:
    Orb will try to extract interesting information about services running
    on machines discovered (ex: OS, vendor, version, cpe, cvs):

    --no-banner         disable extract banners from services
    --no-cve            disable extract vulnerabilities from CVE
    --no-cvs            disable extract CVS description

  *Reporting*:
    These options can be used to specify exporting methods for your
    results. You can choose multiple:

    --no-log            disable generate reports
    --json=JSON         generate json report (ex: --json='foo.json')

```

#### Methods

  - You can select a set of options organized by footprinting method. 

    For this release:

     + Passive:
       - Search for public records
       - Search for deep web records
       - Search for social records
       - Search for news records
       - Extract whois information
       - Discover subdomains (using non intrusive methods)
       - Not scan ports on machines
       - Not scan DNS records
       - Not scan NS records
       - Not scan MX records
       - Not banner grabbing

       *Ex: python3 orb --spell 'target' --passive

     + Active:
       - Opposite to 'Passive' method.

       *Ex: python3 orb --spell='target' --active


#### Search Engines

  - You can set different search engines to gather public records from the Internet.

    For this release (by default: DuckDuckGo):

     + Supported:
       - Duck (duckduckgo.com) [11/01/2020]
       - Bing (bing.com) [11/01/2020]
       - Torch! (deep web) [11/01/2020]

       *Ex: python3 orb --spell='target' --se='bing'

  - Also you can set the location for search engine to retrieve more accurate information
    about your target.

    For example, if is located in Spain you can try to use 'yahoo.es' servers:

       *Ex: python3 orb --spell='target' --se='bing' --se-ext='es' (france=fr, italy=it, etc...)

  - You can search massively using all search engines with:

       *Ex: python3 orb --spell='target' --sa

    These options can be combined:

       *Ex: python3 orb --spell='target' --sa --se-ext='nl'


#### Public Records

  - Orb will search on the WWW for interesting public records. 
 
    But is important to set what is "interesting" for you. For that you can create a list of sources
    organized by some non variable categories: social and news.

    It is added to the tool an example folder for Spain to see how works:

       *Ex: python3 orb --spell='target' --social-f='core/sources/spain/social.txt' --news-f='core/sources/spain/news.txt'

    You should try to build your own sources. 

    By default it is using most ranked Alexa.com services short by category. So you will have a nice global scope from
    the beginning.


#### Domains

  - You can set which domain extensions do you want to use to perform footprinting tasks.

    By default, Orb will use IANA supported domains. But you can set your own manually:

       *Ex: python3 orb --spell='target' --ext='.com,.net,.org'

    Or directly set a list from a file (examples provided):
     
       *Ex: python3 orb --spell='target' --ext-f='core/sources/user-exts.txt'


####  Whois

  - Orb will search on 'Whois' records for registrant information.

```
       *Output example*:
       -----------------
       -Domain: microsoft.com
       -Registrant: MARKMONITOR INC.
       -Creation date: 1991-05-02 00:00:00
       -Expiration: 2021-05-03 00:00:00
       -Last update: 2014-10-09 00:00:00
       -----------------
```

####  Subdomains

  - Orb will try to discover info about subdomains.

    For this release it is using a passive method with search engines (not bruteforcing).


####  DNS

  - Orb will try to discover info about DNS records and machines running them.

    You can set which DNS resolvers (Google used by default) do you want to use for that tasks:
      
       *Ex: python3 orb --spell='target' --resolver='8.8.8.8,8.8.8.4'


####  Port Scanning

  - Orb will use Nmap -python lib wrapper- to perform port scanning tasks.

    You can set protocol type to only TCP (UDP+TCP by default) with:

       *Ex: python3 orb --spell='target' --scan-tcp

    Or select which ports do you want to try with:

       *Ex: python3 orb --spell='target' --scan-ports='21-443'

    ** Port scanner will show you only 'Open' ports on machines. 

    You can see also 'Filtered' ports with:

       *Ex: python3 orb --spell='target' --scan-ports='21-443' --show-filtered


####  Banner Grabbing

  - Orb will try to extract interesting information about services running
    on machines discovered (ex: OS, vendor, version, cpe, cve, cvs):

```
       *Output example*:
       -----------------
       - IP: XXX.XXX.XXX.XXX
         * State : up
          - Protocol : tcp
            + Port: 80 ( open ) - IBM WebSEAL reverse http proxy  |  http-proxy  
              + CVE-2014-0963 -> https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0963
                -----
                Last updated: 3/27/2016 2:37:25 PM
                CVE Publication rate: 11.13
                The Reverse Proxy feature in IBM Global Security Kit (aka GSKit) in IBM Security Access Manager (ISAM) for Web 7.0 before 7.0.0-ISS-SAM-IF0006 and 8.0 before 8.0.0.3-ISS-WGA-IF0002 allows remote attackers to cause a denial of service (infinite loop) via crafted SSL messages.
       -----------------
```

####  Reporting

  - Orb will log all tasks and results organizing them by target on a folder: 'reports/'. 

    You can launch the tool without any log adding:

        *Ex: python3 orb --spell='target' --no-log

  - For verbose output you can use:

        *Ex: python3 orb --spell='target' -v

  - Also you can generate a JSON report only with valid data gathered with:

        *Ex: python3 orb --spell='target' --json='target.json'


### Contribute: 

  To make donations use the following hash:
  
      - Bitcoin: 19aXfJtoYJUoXEZtjNwsah2JKN9CK5Pcjw


### Contact

  Please report any problems you encounter using/installing Orb to:

      - psy (epsylon@riseup.net)

