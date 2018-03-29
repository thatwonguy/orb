#!/usr/bin/env python 
# -*- coding: utf-8 -*-"
"""
This file is part of the orb project, https://orb.03c8.net

Orb - 2016/2017/2018 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with RedSquat; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
from options import OrbOptions
from update import Updater
from orb import ClientThread
import webbrowser, socket, traceback, sys, urllib2, urllib, re, urlparse, os, datetime, random
import json

# ask for libs
try:
    import whois
except:
    print "[Warning] - Error importing: whois lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-whois\n"
    print "[Source] - Pypi-whois: https://pypi.python.org/pypi/whois\n"
    sys.exit(2)
try:
    import nmap
except:
    print "[Warning] - Error importing: nmap lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-nmap\n"
    print "[Source] - python-nmap: https://pypi.python.org/pypi/python-nmap\n"
    sys.exit(2)
try:
    import dns.resolver
except:
    print "[Warning] - Error importing: dns lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-dns\n"
    print "[Source] - Pydnspython: https://pypi.python.org/pypi/dnspython\n"
    sys.exit(2)

DEBUG = 0

class Orb(object):
    def __init__(self):
        self.search_engines = [] # available search engines
        #self.search_engines.append('duck') -> deprecated [27/03/2018]
        #self.search_engines.append('google') -> deprecated [27/03/2018]
        self.search_engines.append('bing')
        self.search_engines.append('yahoo')
        #self.search_engines.append('yandex') -> deprecated [27/03/2018]
        self.engine_fail = False # search engines controller
        self.dns_Amachines = [] # used to check if ip = DNS-A records
        self.socials = None # used to get social links from source file
        self.news = None # used to get news links from source file
        self.url_links = [] #  urls extracted from search engines
        self.sub_links = [] #  subdomains extracted from search engines
        self.extract_wikipedia_record = True # used to not repeat wikipedia descriptions
        self.extract_financial_record = True # used to not repeat financial records
        self.extract_ranked_links = False # used to extract ranked links on search engines
        self.top_ranked = {}
        self.wikipedia_texts = [] # wikipedia descriptions
        self.social_links = {}
        self.news_links = {}
        self.ranked_record = 0
        self.agents = [] # user-agents
        self.ips_scanner = [] # IPs related with scanner without dns records
        f = open("core/sources/user-agents.txt").readlines()
        for line in f:
            self.agents.append(line)

    def set_options(self, options):
        self.options = options

    def create_options(self, args=None):
        self.optionParser = OrbOptions()
        self.options = self.optionParser.get_options(args)
        if not self.options:
            return False
        return self.options

    def banner(self):
        print '='*75, "\n"
        print "  _|_|              _|        "
        print "_|    _|  _|  _|_|  _|_|_|    "
        print "_|    _|  _|_|      _|    _|  "
        print "_|    _|  _|        _|    _|  "
        print "  _|_|    _|        _|_|_|   "
        print self.optionParser.description, "\n"
        print '='*75

    def try_running(self, func, error, args=None):
        options = self.options
        args = args or []
        try:
            return func(*args)
        except Exception as e:
            print(error, "error")
            if DEBUG:
                traceback.print_exc()

    def generate_report(self): # generate raw log/report
        if not os.path.exists('reports/'):
            os.makedirs('reports/')
        if not self.options.gui: # generate report when no gui
            if not os.path.exists('reports/' + self.options.target):
                os.makedirs('reports/' + self.options.target)
            namefile = self.options.target + "_" + str(datetime.datetime.now())
            if self.options.verbose:
                print "\n[Verbose] - Generating log: " + 'reports/' + self.options.target + "/" + namefile + ".raw", "\n"
            self.report = open('reports/' + self.options.target + "/" + namefile + ".raw", 'a') # generate .raw file

    def generate_json(self): # generate json report
        if not os.path.exists('reports/'):
            os.makedirs('reports/')
        if not self.options.gui: # generate report when no gui
            if not os.path.exists('reports/' + self.options.target):
                os.makedirs('reports/' + self.options.target)
            namefile = self.options.json
            if self.options.verbose:
                print "[Verbose] - Generating JSON: " + 'reports/' + self.options.target + "/" + namefile, "\n"
            if os.path.exists('reports/' + self.options.target + "/" + namefile):
                os.remove('reports/' + self.options.target + "/" + namefile) # remove previous report if exists
            self.json_report = open('reports/' + self.options.target + "/" + namefile, 'w') # generate new .json file each time

    def send_request(self, url): # send requests unique point
        user_agent = random.choice(self.agents).strip() # set random user-agent
        referer = '127.0.0.1' # set referer to localhost / WAF black magic!
        headers = {'User-Agent' : user_agent, 'Referer' : referer}
        req = urllib2.Request(url, None, headers)
        req_reply = urllib2.urlopen(req).read()
        return req_reply

    #def search_using_duck(self, target): # duckduckgo.com
    #    url = 'https://duckduckgo.com/html/?'
    #    if self.extract_ranked_links == True: # extract ranked links
    #        q = 'inurl:"' + str(target) + '"' # ex: inurl:"target"
    #    else: # extract subdomains
    #        q = 'site:.' + str(target) # ex: site:.target.com 
    #    query_string = { 'q':q}
    #    data = urllib.urlencode(query_string)
    #    url = url + data
    #    try:
    #        req_reply = self.send_request(url)
    #    except:
    #        return
    #    regex_s = '<a class="result__url" href="(.+?)">' # regex magics (extract urls)
    #    pattern_s = re.compile(regex_s)
    #    url_links = re.findall(pattern_s, req_reply)
    #    return url_links

    #def search_using_google(self, target): # google.com
    #    if self.options.engineloc: # set engine location to increase responses
    #        url = 'https://www.google.' + self.options.engineloc + '/xhtml?'
    #    else:
    #        url = 'https://www.google.com/xhtml?'
    #    if self.extract_ranked_links == True: # extract ranked links
    #        q = 'inurl:"' + str(target) + '"' # ex: inurl:"target"
    #    else: # extract subdomains
    #        q = 'site:.' + str(target) # ex: site:.target.com 
    #    start = 0 # set index number of first entry
    #    num = 50 # 5 pages
    #    gws_rd = 'ssl' # set SSL as default
    #    query_string = { 'q':q, 'start':start, 'num':num, 'gws_rd':gws_rd }
    #    data = urllib.urlencode(query_string)
    #    url = url + data
    #    try:
    #        req_reply = self.send_request(url)
    #    except:
    #        return
    #    regex = '<h3 class="r"><a href="/url(.+?)">' # regex magics
    #    pattern = re.compile(regex)
    #    url_links = re.findall(pattern, req_reply)
    #    return url_links

    def search_using_bing(self, target): # bing.com
        url = 'https://www.bing.com/search?'
        if self.extract_ranked_links == True: # extract ranked links
            q = str(target) # inurl not allow on bing
        else: # extract subdomains
            q = 'site:.' + str(target) # ex: site:.target.com 
        start = 0 # set index number of first entry
        if self.options.engineloc: # add search engine location on query: &cc=
            query_string = { 'q':q, 'first':start, 'cc':self.options.engineloc}
        else:
            query_string = { 'q':q, 'first':start }
        data = urllib.urlencode(query_string)
        url = url + data
        try:
            req_reply = self.send_request(url)
        except:
            return
        regex = '<li class="b_algo"><h2><a href="(.+?)">' # regex magics
        pattern = re.compile(regex)
        url_links = re.findall(pattern, req_reply)
        return url_links

    def search_using_yahoo(self, target): # yahoo.com
        if self.options.engineloc: # set engine location to increase responses
            url = 'https://' + self.options.engineloc + '.search.yahoo.com/search?'
        else:
            url = 'https://search.yahoo.com/search?'
        if self.extract_ranked_links == True: # extract ranked links
            q = str(target)
        else: # extract subdomains
            q = '.' + str(target) 
        start = 0 # set index number of first entry
        query_string = { 'q':q, 'first':start, 'ei':'UTF-8', 'nojs':1 }
        data = urllib.urlencode(query_string)
        url = url + data
        try:
            req_reply = self.send_request(url)
        except:
            return
        regex = 'RU=(.+?)/RK=' # regex magics [27/03/2018]
        pattern = re.compile(regex)
        url_links = re.findall(pattern, req_reply)
        return url_links

    #def search_using_yandex(self, target): # yandex.com
    #    url = 'https://yandex.com/search/?'
    #    if self.extract_ranked_links == True: # extract ranked links
    #        q = str(target)
    #    else: # extract subdomains
    #        q = 'site:.' + str(target)
    #    start = 0 # set index number of first entry
    #    # generate random number on range 1-9999999999 with float point 
    #    # to provide a fake redircnt (ex: 1458153459.1) / black magic!
    #    try:
    #        import random
    #        num = random.uniform(0, 9999999999)
    #    except:
    #        num = 1458153459.1
    #    query_string = { 'text':q, 'p':start , 'redircnt':num}
    #    data = urllib.urlencode(query_string)
    #    url = url + data
    #    try:
    #        req_reply = self.send_request(url)
    #    except:
    #        return
    #    regex = '<a class="link serp-url__link" target="_blank" href="(.+?)"' # regex magics 16/03/2016
    #    pattern = re.compile(regex)
    #    url_links = re.findall(pattern, req_reply)
    #    return url_links

    def search_using_torch(self, target): # http://xmh57jrzrnw6insl.onion
        try:
            url = 'http://xmh57jrzrnw6insl.onion/4a1f6b371c/search.cgi?' # [28/03/2018] https://onion+hash+search.cgi
            q = str(target)
            start = 0
            query_string = { 'q':q, 'cmd':'Search!' }
            data = urllib.urlencode(query_string)
            url = url + data
            try:
                req_reply = self.send_request(url)
            except:
                print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("\n- Deep Web: Not found!\n\n")
                return
            if "No documents were found" in req_reply: # no records found
                print "[Info] - No documents were found!"
                if not self.options.nolog: # generate log
                    self.report.write("- Deep Web: Not found!\n\n")
            else:
                regex = '<A HREF="(.+?)" TARGET' # regex magics - 26/03/2016
                pattern = re.compile(regex)
                url_links = re.findall(pattern, req_reply)
                for url in url_links:
                    print "- Onion URL ->", url
                    if not self.options.nolog: # generate log
                        self.report.write("- Onion URL -> " + url + "\n")
                        if self.options.json: # write reply to json
                            self.json_report.write(json.dumps(['Deep Web',{'Onion': url}], separators=(',', ':')))
                if not self.options.nolog: # generate log
                    self.report.write("\n") # zen
        except: # return when fails
            print "- Not found!"
            if not self.options.nolog: # generate log
                self.report.write("\n- Deep Web: Not found!\n\n")
            return

    def extract_financial(self, target): # extract financial records
        try: # search on yahoo financial
            url = 'https://finance.yahoo.com/lookup?' # [29/03/2018]
            s = str(self.options.target).upper() # uppercase required
            query_string = {'s':s}
            data = urllib.urlencode(query_string)
            url = url + data
            if self.options.verbose:
                print "\n[Verbose] - Financial query used:", url + "\n"
            try:
                req_reply = self.send_request(url)
            except:
                print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("\n- Financial: Not found!\n")
                self.extract_financial_record = False
                return
            regex = '{"exchange":(.+?)"}' # regex magics [28/03/2018]
            pattern = re.compile(regex)
            records = re.findall(pattern, req_reply)
            for record in records:
                regex2 = '"symbol":"(.+?)","industryLink' # regex magics [28/03/2018]
                pattern2 = re.compile(regex2)
                symbol = re.findall(pattern2, record)
                regex3 = '"companyName":"(.+?)","industryName"' # regex magics [28/03/2018]
                pattern3 = re.compile(regex3)
                name = re.findall(pattern3, record)
                sep = '"lastValue":"' # regex magics [28/03/2018]
                prize = record.split(sep, 1)[1]
                if 'industryName' in str(name): # parse empty name
                    name = "['']"
                print "- SYMBOL:", symbol, "-> Name:", name, "-> Last prize:", prize
                if not self.options.nolog: # generate log
                    self.report.write("- SYMBOL: " + str(symbol) + " -> Name: " + str(name) + " -> Last prize: " + str(prize) + "\n")
                    if self.options.json: # write reply to json
                        self.json_report.write(json.dumps(['Financial',{'SYMBOL': symbol,'Name': name,'Last prize': prize}], separators=(',', ':')))
            self.extract_financial_record = False
            if not self.options.nolog: # generate log
                self.report.write("\n") # raw format task
        except: # return when fails
            print "[Info] - Financial: Not found!\n"
            if not self.options.nolog: # generate log
                self.report.write("\n- Financial: Not found!\n")
            self.extract_financial_record = False
            return

    def extract_social(self, url): # extract social links
        if self.options.public: # safe/return when no extract public records option
            return
        if self.options.social: # safe/return when no extract social records option
            return
        for s in self.socials:
            if s in url: # found record
                self.social_links[s] = url # add s/url to dict
            else:
                pass

    def extract_news(self, url): # extract news links (using a list from file)
        if self.options.public: # safe/return when no extract public records option
            return
        if self.options.news: # safe/return when no extract news records option
            return
        for n in self.news:
            if n in url: # found record
                self.news_links[n] = url # add n/url to dict
            else:
                pass

    def extract_wikipedia(self, url): # extract wikipedia info
        try:
            req_reply = self.send_request(url)
        except:
            return
        regex = '<p><b>(.+?)</p>' # regex magics (description)
        pattern = re.compile(regex)
        descr = re.findall(pattern, req_reply)
        for d in descr:
            d_cleanner = re.compile('<.*?>') # clean descriptions
            d_clean = re.sub(d_cleanner,'', d)
            wikipedia = re.sub(r'\[.*?\]\ *', '', d_clean)
        if "may refer to" in wikipedia:
            wikipedia = "There are multiple records for this entry -> " + str(url)
        return wikipedia

    def extract_from_engine(self, engine, target): # search using engine
        #if engine == "duck": # using duck
        #    url_links = self.search_using_duck(target)
        #if engine == "google": # using google
        #    url_links = self.search_using_google(target)
        if engine == "bing": # using bing
            url_links = self.search_using_bing(target)
        if engine == "yahoo": #using yahoo
            url_links = self.search_using_yahoo(target)
        #if engine == "yandex": #using yandex
        #    url_links = self.search_using_yandex(target)
        if not url_links: # not records found
            self.engine_fail = True
        else:     
            for url in url_links:
                if engine == "yahoo" or engine == "bing": # post-parse regex magics
                    sep = '"'
                    url = url.split(sep, 1)[0]
                    url = urllib.unquote(url)
                #if engine == "google":
                #    url = url.replace("?q=", "")
                #    sep = '&amp;sa='
                #    url = url.split(sep, 1)[0]
                if self.extract_ranked_links == True: # ranked links
                    if target in url: # only add urls related with target
                        self.url_links.append(url)
                    if self.ranked_record == 0:
                        if target in url: # only add urls related with target
                            self.top_ranked[engine] = url # add s/url to dict
                            self.ranked_record = self.ranked_record + 1
                else: # subdomains
                    self.sub_links.append(url)
            self.engine_fail = False

    def extract_ranked(self, target, engine): # extract ranked link
        if self.options.public: # safe/return when no extract public records option
            return
        self.extract_ranked_links = True # used to perform different queries to search engines
        self.ranked_record = 0 # extract ranked link
        self.extract_from_engine(engine, target)
        self.extract_ranked_links = False # list semaphore to off

    def public_records_output(self): # output public records after parsing
        # extract and order data gathered + report when found
        print "="*14
        print "*Top Ranked*:"
        print "="*14
        if not self.top_ranked:
            print "- Not found!"
            if not self.options.nolog: # generate log
                self.report.write("\n- Top Ranked: Not found!\n\n")
        else:
            for key,val in self.top_ranked.items():
                print("- {} -> {}".format(key, val))
                if not self.options.nolog: # generate log
                    self.report.write("- Top ranked: " + key + " -> " + val + "\n")
                    if self.options.json: # write reply to json
                        self.json_report.write(json.dumps(['Ranked',{'Engine': key, 'Top': val}], separators=(',', ':')))
            if not self.options.nolog: # generate log
                self.report.write("\n") # raw format task
        if self.extract_wikipedia_record == True: # not need to repeat wikipedia descriptions on each extension
            print "="*14
            print "*Wikipedia*:"
            print "="*14
            if not self.wikipedia_texts:
                print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("- Wikipedia: Not found!\n\n")
            else:
                for wikipedia in self.wikipedia_texts:
                    if wikipedia is not None:
                        print "-", wikipedia
                        if not self.options.nolog: # generate log
                            self.report.write("- " + wikipedia + "\n")
                            if self.options.json: # write reply to json (non parsed ascii)
                                self.json_report.write(json.dumps(['Wikipedia',{'Description': wikipedia}], separators=(',', ':'), ensure_ascii=False))
                if wikipedia is None:
                    print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("\n") # raw format task
        if not self.options.social:
            print "="*14
            print "*Social*:"
            print "="*14
            if not self.social_links:
                print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("- Social: Not found!\n\n")
            else:
                for key,val in self.social_links.items():
                    print("- {} -> {}".format(key, val))
                    if not self.options.nolog: # generate log
                        self.report.write("- " + key + " -> " + val + "\n")
                        if self.options.json: # write reply to json
                            self.json_report.write(json.dumps(['Social',{key:val}], separators=(',', ':')))
                if not self.options.nolog: # generate log
                    self.report.write("\n") # raw format task
        if not self.options.news:
            print "="*14
            print "*News*:"
            print "="*14
            if not self.news_links:
                print "- Not found!"
                if not self.options.nolog: # generate log
                    self.report.write("- News: Not found!\n\n")
            else:
                for key,val in self.news_links.items():
                    print("- {} -> {}".format(key, val))
                    if not self.options.nolog: # generate log
                        self.report.write("- " + key + " -> " + val + "\n")
                        if self.options.json: # write reply to json
                            self.json_report.write(json.dumps(['News',{key:val}], separators=(',', ':')))
                if not self.options.nolog: # generate log
                    self.report.write("\n") # raw format task

    def extract_public(self, target): # extract general public records
        if self.options.public: # safe/return when no extract public records option
            return
        if self.options.allengines: # search using all search engines available (pass to next when fails)
            for engine in self.search_engines:
                self.extract_ranked(target, engine)
        else:
            if self.options.engine:
                if self.options.engine in self.search_engines:
                    engine = str(self.options.engine)
                else:
                    engine = "yahoo"
                    print "\n- You are setting a non supported search engine. Using default: " + engine + "\n"
            else:
                engine = "yahoo" # used by default
            self.extract_ranked(target, engine)
        if self.engine_fail == True: # pass other tests when no urls
            if not self.options.allengines:
                print "\n- [" + target + "] -> Not any link found using:",  engine + "\n"
            if not self.options.nolog: # generate log
                self.report.write("\n***[Info] - [" + target + "] -> Not any link found using: " + engine + "\n\n")
        else:
            for url in self.url_links: # search on results retrieved by all engines used
                #if self.extract_wikipedia_record == True: # extract mode
                #    if "wikipedia.org" in url: # wikipedia record!
                #        wikipedia = self.extract_wikipedia(url) # extract data from wikipedia
                #        if wikipedia not in self.wikipedia_texts: # not repeat entries
                #            self.wikipedia_texts.append(wikipedia)
                if not self.options.social:
                    self.extract_social(url)
                if not self.options.news:
                    self.extract_news(url)
            if self.extract_wikipedia_record == True: # visit directly to wikipedia when is not located any record by search engines
                url_wiki = "https://en.wikipedia.org/wiki/" + str(target).title() # wikipedia default path to extract records
                if self.options.verbose:
                    print "\n[Verbose] - Wikipedia query used:", url_wiki + "\n"
                wikipedia = self.extract_wikipedia(url_wiki) # extract data from wikipedia
                if wikipedia not in self.wikipedia_texts: # not repeat entries
                    self.wikipedia_texts.append(wikipedia)
        self.public_records_output() # output parsed public records
        if not self.options.deep: # search for deep web records
            print "="*14
            print "*Deep Web*:"
            print "="*14
            self.search_using_torch(target)
        if not self.options.financial: # search for financial records
            if self.extract_financial_record == True: # extract mode
                print "="*14
                print "*Financial*:"
                print "="*14
                self.extract_financial(target)
                self.extract_financial_record = False

    def extract_whois(self, target): # extract whois data from target domain
        print "="*14
        print "*Whois*:"
        print "="*14
        try:
            domain = whois.query(target, ignore_returncode=True) # ignore return code
            if domain.creation_date is None: # return when no creation date
                print "- Not found!\n"
                if not self.options.nolog: # generate log
                    self.report.write("- Whois: Not found!\n\n")
                return
        except: # return when fails performing query
            print "- Not found!"
            if not self.options.nolog: # generate log
                self.report.write("- Whois: Not found!\n\n")
            return
        else:
            print "- Domain: " + str(domain.name)
            print "- Registrant: " + str(domain.registrar)
            print "- Creation date: " + str(domain.creation_date)
            print "- Expiration: " + str(domain.expiration_date)
            print "- Last update: " + str(domain.last_updated)
            if not self.options.nolog: # write reply to log
                self.report.write("- Domain: " + str(domain.name) + "\n")
                self.report.write("- Registrant: " + str(domain.registrar) + "\n")
                self.report.write("- Creation date: " + str(domain.creation_date) + "\n")
                self.report.write("- Expiration: " + str(domain.expiration_date) + "\n")
                self.report.write("- Last update: " + str(domain.last_updated) + "\n")
                if self.options.json: # write reply to json
                    self.json_report.write(json.dumps(['Whois',{'Domain': str(domain.name), 'Registrant': str(domain.registrar),'Creation date': str(domain.creation_date),'Expiration': str(domain.expiration_date),'Last update': str(domain.last_updated)}], separators=(',', ':')))

    def extract_cvs(self, cve_info): # using CVE extended detail from web.nvd.nist.gov
        url = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId'
        q = str(cve_info) # product extracted from scanner  
        query_string = { '':q}
        data = urllib.urlencode(query_string)
        url = url + data
        if self.options.verbose:
            print "\n[Verbose] - CVS database query used:", url + "\n"
        try:
            req_reply = self.send_request(url)
        except:
            if self.options.verbose:
                print('\n[Error] - Cannot extract CVS records...\n')
            return
        regex_cvs = '<p data-testid="vuln-description">(.+?)</p>\r' # regex magics [28/03/2018]
        pattern_cvs = re.compile(regex_cvs)
        cvs = re.findall(pattern_cvs, req_reply)
        print "" # zen output
        for cvs_desc in cvs: 
            cvs_desc = cvs_desc.replace('This is a potential security issue, you are being redirected to <a href="http://nvd.nist.gov">http://nvd.nist.gov</a','')
            cvs_desc = cvs_desc.replace("<strong>", "")
            cvs_desc = cvs_desc.replace("</strong>", "")
            sep = '<'
            cvs_desc = cvs_desc.split(sep, 1)[0]
            cvs_desc = cvs_desc.replace(">","-----") 
            print "          ", cvs_desc # 10 tab for zen
            if not self.options.nolog: # write reply to log
                self.report.write("          " + cvs_desc + "\n")
                if self.options.json: # write reply to json
                    self.json_report.write(json.dumps(['CVS',{'Description': str(cvs_desc)}], separators=(',', ':')))

    def extract_cve(self, product): # extract vulnerabilities from CVE database
        url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword'
        q = str(product) # product extracted from scanner 
        query_string = { '':q}
        data = urllib.urlencode(query_string)
        url = url + data
        if self.options.verbose:
            print "\n[Verbose] - CVE database query used:", url
        try:
            req_reply = self.send_request(url)
        except:
            if self.options.verbose:
                print('\n[Error] - Cannot resolve CVE records...\n')
            return
        if req_reply == "": # no records found
            print "- Not any record found on CVE database!"
            if not self.options.nolog: # write reply to log
                self.report.write("- Not any record found on CVE database!" + "\n")
        regex_s = '<td valign="top" nowrap="nowrap"><a href="(.+?)">' # regex magics
        pattern_s = re.compile(regex_s)
        CVE_links = re.findall(pattern_s, req_reply)
        for cve in CVE_links:
            cve_info = cve.replace("/cgi-bin/cvename.cgi?name=","")
            print "\n        +", cve_info, "->", "https://cve.mitre.org" + cve # 8 tab for zen
            if not self.options.nolog: # write reply to log
                self.report.write("\n        + " + cve_info + "->" + "https://cve.mitre.org" + cve + "\n")
                if self.options.json: # write reply to json
                    self.json_report.write(json.dumps(['CVE',{'ID': str(cve_info), 'Link': "https://cve.mitre.org" + str(cve)}], separators=(',', ':')))
            if not self.options.cvs: # extract description from vulnerability (CVS)
                self.extract_cvs(cve_info)

    def search_subdomains(self, target): # try to extract subdomains from target domain (1. using search engines)
        # extract subdomains using search engines results (taking data from 'past')
        self.extract_ranked_links = False # use correct subdomains query term on search engines
        print "="*14
        print "*Subdomains*:"
        print "="*14
        for engine in self.search_engines:
            self.extract_from_engine(engine, target)
        if not self.sub_links: # not records found
            print "- Not any subdomain found!"
            if not self.options.nolog: # write reply to log
                self.report.write("- Subdomains: Not any found!" + "\n\n")
        else:
            record_s = 0
            short = "." + str(target)
            subdomains = []
            for url in self.sub_links:
                if "www." in url:
                    url = url.replace("www.", "") # remove www.
                if short in url: # subdomain
                    url_s = urlparse.urlparse(url)
                    subdomain = str(url_s.hostname.split('.')[0] + "." + str(target))
                    if not subdomain in subdomains:
                        subdomains.append(subdomain)
            for s in subdomains:
                print "- " + s
                if not self.options.nolog: # write reply to log
                    self.report.write("- Subdomain: " + s + "\n")
                    if self.options.json: # write reply to json
                        self.json_report.write(json.dumps(['Subdomains',{'Subdomain': str(s)}], separators=(',', ':')))
                record_s = record_s + 1
            if not self.options.nolog: # generate log
                self.report.write("\n") # zen
            if record_s == 0:
                print "- Not any subdomain found!"
                if not self.options.nolog: # write reply to log
                    self.report.write("- Subdomains: Not any found!" + "\n\n")

    def resolve_ip(self, target): # try to resolve an ip from target domain
        data = socket.gethostbyname_ex(target) # reverse resolve target
        for ip in data[2]:
            self.ip = ip
            self.ips_scanner.append(ip) # add to list of scanner found IPs without DNS
            print "- " + str(ip)
            if not self.options.nolog: # write reply to log
                self.report.write("- IP: " + str(ip) + "\n")
                if self.options.json: # write reply to json
                    self.json_report.write(json.dumps(['Server',{'IP': str(ip)}], separators=(',', ':')))
        if not self.options.nolog: # generate log
            self.report.write("\n") # zen
        return ip

    def scan_target(self, target): # try to discover Open Ports
        if self.options.scanner: # safe/return when no scanning option
            return
        open_ports = 0 # open ports counter
        if not self.options.proto:
            proto = "TCP+UDP"
        else:
            proto = "TCP"
            #proto = str(self.options.proto)
            #proto = proto.upper()
        nm = nmap.PortScanner()
        if self.options.ports:
            ports = self.options.ports
        else:
            ports = '1-65535' # scanning all ports by default (1-65535)
        #if proto == "UDP": # scan UDP ports (UDP Scan)   
        #    nm.scan(str(target), str(ports), arguments='-sU -sV', sudo=False)
        #    if self.options.verbose:
        #        print "-Using:", nm.command_line()
        if proto == "TCP": # scan TCP ports (TCP connect()+Service scan)   
            nm.scan(str(target), str(ports), arguments='-sT -sV', sudo=False)
            if self.options.verbose:
                print "-Using:", nm.command_line()
        elif proto == "TCP+UDP": # scan TCP+UDP ports (NoPing+Service scan)
            nm.scan(str(target), str(ports), arguments='-PN -sV', sudo=False)
            if self.options.verbose:
                print "-Using:", nm.command_line()
        #else:
        #    print "\n[Info] - You are not setting a supported protocol. Options are: 'UDP', 'TCP' or 'TCP+UDP'.\n"
        #    nm.scan(str(target), str(ports), arguments='-PN -sV', sudo=False) # (NoPing+Service scan) 
        #    if self.options.verbose:
        #        print "-Using:", nm.command_line()
        for host in nm.all_hosts():
            print('\n   * Host : %s' % host)
            if not self.options.nolog: # write reply to log
                self.report.write('\n   * Host : ' + str(host) + "\n")
            print('   * State : %s' % nm[host].state())
            if not self.options.nolog: # write reply to log
                self.report.write('   * State : ' + str(nm[host].state()) + "\n")
            for proto in nm[host].all_protocols():
                print('    - Protocol : %s' % proto)
                if not self.options.nolog: # write reply to log
                    self.report.write("    - Protocol: " + proto + "\n")
                    if self.options.json: # write json report
                        self.json_report.write(json.dumps(['Scanner',{'Protocol': str(proto)}], separators=(',', ':')))
                lport = nm[host][proto].keys()
                lport.sort()
                for port in lport:
                    if not self.options.banner: # extract banners from services discovered
                        if str(nm[host][proto][port]['state']) == "open": # results open ports+banner
                            print "      + Port:", port, "(", nm[host][proto][port]['state'], ") -", nm[host][proto][port]['product'], " |", nm[host][proto][port]['version'], nm[host][proto][port]['name'], nm[host][proto][port]['extrainfo'], nm[host][proto][port]['cpe']
                            if not self.options.nolog: # write reply to log
                                self.report.write("      + Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ") - " +  str(nm[host][proto][port]['product']) + str(nm[host][proto][port]['version']) + str(nm[host][proto][port]['name']) + str(nm[host][proto][port]['extrainfo']) + str(nm[host][proto][port]['cpe']) + "\n")
                                if self.options.json: # write json report
                                    self.json_report.write(json.dumps(['Scanner',{'Port': str(port), 'State': str(nm[host][proto][port]['state']), 'Version': str(nm[host][proto][port]['version']), 'Name': str(nm[host][proto][port]['name']), 'Info': str(nm[host][proto][port]['extrainfo']), 'CPE': str(nm[host][proto][port]['cpe'])}], separators=(',', ':')))
                            open_ports = open_ports + 1
                            if not self.options.cve: # extract vulnerabilities from CVE (Common Vulnerabilities and Exposures)
                                product = str(nm[host][proto][port]['product'])
                                cve = self.extract_cve(product)
                                print "" # zen output
                    else: # not extract banners
                        if str(nm[host][proto][port]['state']) == "open": # only results when open port
                            print "      + Port:", port, "(", nm[host][proto][port]['state'], ")"
                            if not self.options.nolog: # write reply to log
                                self.report.write("     + Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ")")
                                if self.options.json: # write json report
                                    self.json_report.write(json.dumps(['Scanner',{'Port': str(port), 'State': str(nm[host][proto][port]['state'])}], separators=(',', ':')))
                            open_ports = open_ports + 1
                        if self.options.filtered: # add filtered ports to results
                            if str(nm[host][proto][port]['state']) == "filtered": # results filtered ports (no banners)
                                print "      + Port:", port, "(", nm[host][proto][port]['state'], ")"
                                if not self.options.nolog: # write reply to log
                                    self.report.write("     + Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ")")
                                    if self.options.json: # write json report
                                        self.json_report.write(json.dumps(['Scanner',{'Port': str(port), 'State': str(nm[host][proto][port]['state'])}], separators=(',', ':')))
                if not open_ports > 0:
                    print "\n- Not any open port found!"
                    if not self.options.nolog: # write reply to log
                        self.report.write("\n- Not any open port found + \n\n")

    def resolve_dns(self, target): # try to discover DNS records + perform portscanning
        resolver = dns.resolver.Resolver()
        if self.options.resolv: # use DNS resolver provided by user
            resolvers = str(self.options.resolv)
            resolvers = resolvers.split(",")
            resolver.nameservers = resolvers
            if self.options.verbose:
                print "[Verbose] - Using DNS resolvers: [" + self.options.resolv + "]\n"
        else: # use default Google Inc. DNS resolvers (8.8.8.8, 8.8.4.4)
            resolver.nameservers = ['8.8.8.8', '8.8.4.4'] # google DNS resolvers
            if self.options.verbose:
                print "[Verbose] - Using DNS resolvers: [8.8.8.8, 8.8.4.4]\n"
        try:
            answers = resolver.query(target, "A") # A records
            for rdata in answers:
                print "- [A]:", rdata
                self.dns_Amachines.append(rdata)
                if not self.options.nolog: # write reply to log
                    self.report.write("- DNS [A]: " + str(rdata) + "\n")
                    if self.options.json: # write json report
                        self.json_report.write(json.dumps(['DNS',{'A': str(rdata)}], separators=(',', ':')))
                if not self.options.scanner: # try port-scanner on DNS-A records
                    if not self.options.scandns:
                        scanner = self.scan_target(rdata)
            print "-"*12
            if not self.options.nolog: # write reply to log
                self.report.write("-"*12 + "\n")
        except:
            pass
        try:
            answers = resolver.query(target, "NS") # NS records
            for rdata in answers:
                rdata = str(rdata) # NS records ends with "." (removing)
                rdata = rdata[:-1]
                data = socket.gethostbyname_ex(rdata) # reverse resolve NS server
                for ip in data[2]:
                    self.ip = ip
                print "- [NS]:", rdata, "(" + str(self.ip) + ")"
                if not self.options.nolog: # write reply to log
                    self.report.write("- DNS [NS]: " + str(rdata) + "(" + str(self.ip) + ")" + "\n")
                    if self.options.json: # write json report
                        self.json_report.write(json.dumps(['DNS',{'NS': str(rdata)}], separators=(',', ':')))
                if not self.options.scanner:
                    if not self.options.scandns:
                        if not self.options.scanns: # try port-scanner on DNS-NS records
                            scanner = self.scan_target(rdata)
            print "-"*12
            if not self.options.nolog: # write reply to log
                self.report.write("-"*12 + "\n")
        except:
            pass
        try:
            answers = resolver.query(target, "MX") # MX records
            for rdata in answers:
                rdata = str(rdata) # MX records ends with "." (removing)
                rdata = rdata[:-1]
                rdata = rdata.replace("10 ", "") # MX records starts with "10 " (removing)
                data = socket.gethostbyname_ex(rdata) # reverse resolve MX server (mailserver)
                for ip in data[2]:
                    self.ip = ip
                print "- [MX]:", rdata, "(" + str(self.ip) + ")"
                if not self.options.nolog: # write reply to log
                    self.report.write("- DNS [MX]: " + str(rdata) + "(" + str(self.ip) + ")" + "\n")
                    if self.options.json: # write json report
                        self.json_report.write(json.dumps(['DNS',{'MX': str(rdata)}], separators=(',', ':')))
                if not self.options.scanner: # try port-scanner on DNS-MX records
                    if not self.options.scandns:
                        if not self.options.scanmx:
                            scanner = self.scan_target(rdata)
            print "-"*12
            if not self.options.nolog: # write reply to log
                self.report.write("-"*12 + "\n")
        except: #pass when no MX records
            pass
        try:
            answers = resolver.query(target, "TXT") # TXT records
            for rdata in answers:
                print "- [TXT]:", rdata
                if not self.options.nolog: # write reply to log
                    self.report.write("- DNS [TXT]: " + str(rdata) + "\n")
                    if self.options.json: # write json report
                        self.json_report.write(json.dumps(['DNS',{'TXT': str(rdata)}], separators=(',', ':')))
            print "-"*12
            if not self.options.nolog: # write reply to log
                self.report.write("-"*12 + "\n")
        except: #pass when no TXT records
            pass

    def run(self, opts=None):
        if opts:
            options = self.create_options(opts)
            self.set_options(options)
        options = self.options
        if not self.options.gui: # generate report when no gui
            self.banner()
        # check tor connection
        if options.checktor:
            try:
                print("\nSending request to: https://check.torproject.org\n")
                tor_reply = urllib2.urlopen("https://check.torproject.org").read()
                your_ip = tor_reply.split('<strong>')[1].split('</strong>')[0].strip()
                if not tor_reply or 'Congratulations' not in tor_reply:
                    print("It seems that Tor is not properly set.\n")
                    print("Your IP address appears to be: " + your_ip + "\n")
                else:
                    print("Congratulations!. Tor is properly being used :-)\n")
                    print("Your IP address appears to be: " + your_ip + "\n")
            except:
                print("Cannot reach TOR checker system!. Are you correctly connected?\n")
            sys.exit(2)
       # check/update for latest stable version
        if options.update:
            try:
                print("\nTrying to update automatically to the latest stable version\n")
                Updater()
            except:
                print("\nSomething was wrong!. You should clone Orb manually with:\n")
                print("$ git clone https://github.com/epsylon/orb\n")
            sys.exit(2)
        # logging / reporting
        if not options.nolog: # generate log
            self.generate_report()
            if options.json: # generate json report
                self.generate_json()
        # footprinting (only passive)
        if options.passive:
            self.options.scanner = True # not scan ports on machines
            self.options.scandns = True # not scan on DNS records
            self.options.scanns = True # not scan on NS records
            self.options.scanmx = True # not scan on MX records
            self.options.banner = True # not banner grabbing
            self.options.cve = True # not CVE
            self.options.cvs = True # not CVS
        # footprinting (only active)
        if options.active:
            self.options.public = True # not search for public records
            self.options.financial = True # not search for financial records
            self.options.deep = True # not search for deep web records
            self.options.social = True # not search for social records
            self.options.news = True # not search for news records
            self.options.whois = True # not extract whois information
            self.options.subs = True # not try to discover subdomains (with passive methods) / bruteforce ¿next release? :)
        # footprinting (full) / by default
        if options.target:
            # public records / deepweb, financial, social, news ...
            if not options.public: # search for public records
                print "="*60
                print "[Info] - Retrieving general data ..."
                print "="*60
                if not options.social: # retrieve social urls
                    if not options.socialf: # try default list
                        f = open('core/sources/social.txt')
                    else: # extract social links from list provided by user
                        try:
                            f = open(options.socialf)
                        except:
                            if os.path.exists(options.socialf) == True:
                                print '[Error] - Cannot open:', options.socialf, "\n"
                                return
                            else:
                                print '[Error] - Cannot found:', options.socialf, "\n"
                                return
                    self.socials = f.readlines()
                    self.socials = [ social.replace('\n','') for social in self.socials ]
                    f.close()
                if not options.news: # retrieve news urls
                    if not options.newsf: # try default list
                        f = open('core/sources/news.txt')
                    else: # extract social news from list provided by user
                        try:
                            f = open(options.newsf)
                        except:
                            if os.path.exists(options.newsf) == True:
                                print '[Error] - Cannot open:', options.newsf, "\n"
                                return
                            else:
                                print '[Error] - Cannot found:', options.newsf, "\n"
                                return
                    self.news = f.readlines()
                    self.news = [ new.replace('\n','') for new in self.news ]
                    f.close()
                public = self.extract_public(options.target)
                if not options.nolog: # generate log
                    self.report.write("-"*22 + "\n")
            # domains / extract extensions from source provided (comma separated)
            print "="*60
            print "[Info] - Retrieving data by TLDs ..."
            print "="*60
            tld_record = False # tld records
            self.extract_wikipedia_record = False
            if options.ext: # by user
                extensions = [str(options.ext)]
                extensions = options.ext.split(",")
                print "\n[Info] - Using extensions provided by user...\n"
            elif options.extfile: # from file
                try:
                    print "\n[Info] - Extracting extensions from file...\n"
                    f = open(options.extfile)
                    extensions = f.readlines()
                    extensions = [ ext.replace('\n','') for ext in extensions ]
                    f.close()
                    if not extensions:
                        print "[Error] - Cannot extract 'extensions' from file.\n"
                        return
                except:
                    if os.path.exists(options.extfile) == True:
                        print '[Error] - Cannot open:', options.extfile, "\n"
                        return 
                    else:
                        print '[Error] - Cannot found:', options.extfile, "\n"
                        return
            else: # IANA (default) original + country (09/03/2016)
                print "\n[Info] - Using extensions supported by IANA...\n"
                f = open("core/sources/iana-exts.txt") # extract IANA list provided by default
                extensions = f.readlines()
                extensions = [ ext.replace('\n','') for ext in extensions ]
                f.close()
                if not extensions:
                    print "[Error] - Cannot extract 'IANA extensions' from file.\n"
                    return
            for e in extensions: # extract domain info and perform different tasks
                target = str(options.target + e)
                print "="*40
                print "[Info] - Trying TLD:", target
                print "="*40
                # public records (by extension)
                if not options.public: # search for public records
                    # clear previous data to reuse containers
                    self.url_links[:] = [] # clear a list / black magic!
                    self.top_ranked.clear() # clear top ranked dict
                    self.social_links.clear() # clear social dict
                    self.news_links.clear() # clear news dict
                    public = self.extract_public(target)
                # whois
                if not options.whois: # try to extract whois data
                    if options.verbose:
                        print "\n[Verbose] - Trying whois to: " + target + "\n"
                    whois = self.extract_whois(target)
                # subdomains
                if not options.subs: # try to discover subdomains on target domain
                    if options.verbose:
                        print "\n[Verbose] - Trying to resolve subdomains for:", target, "\n"
                    self.sub_links[:] = [] # clear subs list
                    try:
                        subdomains = self.search_subdomains(target)
                    except:
                        print "- Not any subdomain found using TLD:", target
                        if not options.nolog: # generate log
                            self.report.write("- Subdomains: Not any subdomain found using TLD provided: " + target + "\n\n")
                            if options.json: # generate json
                                self.json_report.write(json.dumps(['Subdomains',{target: 'not any subdomain found'}], separators=(',', ':')))
                # ip
                print "="*14
                print "*IP*:"
                print "="*14
                if options.verbose:
                    print "\n[Verbose] - Trying to resolve IP for:", target, "\n"
                try:
                    ip = self.resolve_ip(target) # try to resolve an ip from target domain
                    tld_record = True
                except:
                    print "Not any IP found using TLD:", target
                    if not options.nolog: # generate log
                        self.report.write("- IP: Not any IP found using TLD provided: " + target + "\n\n")
                        if options.json: # generate json
                            self.json_report.write(json.dumps(['TLD',{target: 'not any IP found'}], separators=(',', ':')))
                    tld_record = False
                # dns + scanning
                if not options.dns: # try to discover DNS records
                    print "="*14
                    print "*DNS records*:"
                    print "="*14
                    if options.verbose:
                        print "\n[Verbose] - Trying to resolve DNS records for:", target, "\n"
                    try:
                        dns = self.resolve_dns(target)
                    except:
                        print "- Not any DNS record found using TLD:", target
                        if not options.nolog: # generate log
                            self.report.write("- DNS: Not any DNS record found using TLD provided: " + target + "\n\n")
                            if options.json: # generate json
                                self.json_report.write(json.dumps(['DNS',{target: 'not any DNS record found'}], separators=(',', ':')))
                # rest of scanning tasks (when ip != DNS[A])
                if not options.scanner and tld_record == True: # try port-scanner on IP
                    if not options.dns: # using DNS A
                        for Amachine in self.dns_Amachines:
                            if str(Amachine) == str(ip):
                                if not options.scandns: # pass when DNS was scanned                               
                                    pass
                                else:
                                    print "[Info] - Trying to discover open ports on:", ip, "\n"
                                    scanner = self.scan_target(ip)
                            else:
                                print "[Info] - Trying to discover open ports on:", ip, "\n"
                                scanner = self.scan_target(ip)
                    else: # only IP test
                        for ip in self.ips_scanner: # scan all ips found without DNS
                            if options.verbose:
                                print "\n[Verbose] - Trying to discover open ports on:", ip, "\n"
                            scanner = self.scan_target(ip)
                print "" # zen output extensions separator
                if not options.nolog:
                    self.report.write("-"*22 + "\n")
            if not options.nolog: # close log (.raw)
                self.report.close()
                if options.json: # close json
                    self.json_report.close()
        # start web-gui
        if options.gui:
            host = '0.0.0.0' # local network
            port = 9999 # local port
            try: 
                webbrowser.open('http://127.0.0.1:9999', new=1)
                tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	        tcpsock.bind((host,port))
	        while True:
	            tcpsock.listen(4)
	            (clientsock, (ip, port)) = tcpsock.accept()
	            newthread = ClientThread(ip, port, clientsock)
                    newthread.start()
            except (KeyboardInterrupt, SystemExit):
                sys.exit()

if __name__ == "__main__":
    app = Orb()
    options = app.create_options()
    if options:
        app.set_options(options)
        app.run()
