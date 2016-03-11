#!/usr/bin/env python 
# -*- coding: utf-8 -*-"
"""
This file is part of the orb project, http://orb.03c8.net

Orb - 2016 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with RedSquat; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
from options import OrbOptions
from orb import ClientThread
import webbrowser, socket, traceback, sys, urllib2, urllib, re, urlparse, os, datetime

DEBUG = 1

class Orb(object):
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

    def run(self, opts=None):
        if opts:
            options = self.create_options(opts)
            self.set_options(options)
        options = self.options

        # check tor connection
        if options.checktor:
            self.banner()
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

        # spell multidimensional footprinting (+reporting)
        if options.target:
            self.banner()
            if not os.path.exists('reports/'):
                os.makedirs('reports/')
            if not os.path.exists('reports/' + options.target):
                os.makedirs('reports/' + options.target)
            namefile = options.target + "_" + str(datetime.datetime.now())
            print "\nGenerating log files at:", 'reports/' + options.target + "/", "\n"
            print "-"*22
            fout = open('reports/' + options.target + "/" + namefile + ".raw", 'a') # generate .raw file
            # level -2: finances (yahoo)
            url = 'https://finance.yahoo.com/q?'
            s = str(options.target).upper() # uppercase required
            query_string = { 's':s}
            data = urllib.urlencode(query_string)
            url = url + data
            if options.verbose:
                print "[Verbose] Trying query to: 'Yahoo' finances database ...\n"
            headers = {'User-Agent' : 'DonutP; Windows98SE', 'Referer' : '127.0.0.1'} 
            try:
                req = urllib2.Request(url, None, headers)
                req_reply = urllib2.urlopen(req).read()
            except:
                print('\n[Error] - Unable to spell an orb ...\n')
                return
            regex = '<div class="hd"><div class="title"><h2>(.+?)</h2>' # regex magics (company)
            pattern = re.compile(regex)
            names = re.findall(pattern, req_reply)
            for name in names:
                print "-Company:", name
                fout.write("Company: " + name + "\n")
            regex2 = '<span class="rtq_dash">-</span>(.+?)</span>' # regex magics (market)
            pattern2 = re.compile(regex2)
            stocks = re.findall(pattern2, req_reply)
            for stock in stocks:
                print "-Market:", stock
                fout.write("Market: " + stock + "\n")
            fout.write("-"*22+ "\n")
            # level -1: social sites- ranked + top
            url = 'https://duckduckgo.com/html/?'
            q = 'inurl:"' + str(options.target) + '"'
            start = 0 
            query_string = { 'q':q, 's':start }
            data = urllib.urlencode(query_string)
            url = url + data
            headers = {'User-Agent' : 'Crawler@alexa.com', 'Referer' : 'alexa.com'} 
            try:
                req = urllib2.Request(url, None, headers)
                req_reply = urllib2.urlopen(req).read()
            except:
                print('\n[Error] - Your orb has been destroyed ...\n')
                return
            if req_reply == "": # no records found.
                print "- Not any record found on search engine"
                fout.write("- Not any record found on search engine" + "\n")
            regex = '<a class="result__url" href="(.+?)">' # regex magics
            pattern = re.compile(regex)
            url_links = re.findall(pattern, req_reply)
            print "="*60
            print "Gathering ranked public links..."
            print "="*60
            ranked = 0
            record = 0
            for url in url_links:
                if ranked == 0:
                    print "+TOP: " + url
                    fout.write("+TOP: "+ url+ "\n")
                    ranked = ranked + 1
                    print "-"*22
                    fout.write("-"*22 + "\n")
                if "wikipedia.org" in url: # wikipedia
                    print "-Wikipedia: " + url
                    fout.write("Wikipedia: " + url + "\n")
                    record = record + 1
                elif "youtube.com" in url: # youtube
                    print "-Youtube: " + url
                    fout.write("Youtube: " + url + "\n")
                    record = record + 1
                elif "linkedin.com" in url: # linkedin
                    print "-Linkedin: " + url
                    fout.write("Linkedin: " + url + "\n")
                    record = record + 1
                elif "github.com" in url: # github
                    print "-Github: " + url
                    fout.write("Github: " + url + "\n")
                    record = record + 1
                elif "twitter.com" in url: # twitter
                    print "-Twitter: " + url
                    fout.write("Twitter: " + url + "\n")
                    record = record + 1
                elif "facebook.com" in url: # facebook
                    print "-Facebook: " + url
                    fout.write("Facebook: " + url + "\n")
                    record = record + 1
                elif "pinterest.com" in url: # pinterest
                    print "-Pinterest: " + url
                    fout.write("Pinterest: " + url + "\n")
                    record = record + 1
                elif "plus.google.com" in url: # google+
                    print "-Google+: " + url
                    fout.write("Google+: " + url + "\n")
                    record = record + 1
            if record == 0:
                print "- Not any record found on social sites"
                fout.write("- Not any record found on social sites" + "\n")

            # level 0: targeting (multidimensional extensions) / ip + dns records
            print "="*60
            print "Retrieving data by TLDs ..."
            print "="*60
            tld_record = 0
            try:
                import whois
            except:
                print "[Warning] Error importing: whois lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-whois\n"
                sys.exit(2)
            try:
                import nmap
            except:
                print "[Warning] Error importing: nmap lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-nmap\n"
                sys.exit(2)
            try:
                import dns.resolver
            except:
                print "[Warning] Error importing: dns lib. \n\n On Debian based systems:\n\n $ sudo apt-get install python-dns\n"
                sys.exit(2)

            extensions = ['.com', '.org', '.net', '.ac', '.ad', '.ae', '.af', '.ag', '.ai', '.al', '.am', '.an', '.ao', '.aq', '.ar', '.as', '.at', '.au', '.aw', '.ax', '.az', '.ba', '.bb', '.bd', '.be', '.bf', '.bg', '.bh', '.bi', '.bj', '.bm', '.bn', '.bo', '.br', '.bs', '.bt', '.bv', '.bw', '.by', '.bz', '.ca', '.cc', '.cd', '.cf', '.cg', '.ch', '.ci', '.ck', '.cl', '.cm', '.cn', '.co', '.cr', '.cs', '.cu', '.cv', '.cx', '.cy', '.cz', '.dd', '.de', '.dj', '.dk', '.dm', '.do', '.dz', '.ec', '.ee', '.eg', '.eh', '.er', '.es', '.et', '.eu', '.fi', '.fj', '.fk', '.fm', '.fo', '.fr', '.ga', '.gb', '.gd', '.ge', '.gf', '.gg', '.gh', '.gi', '.gl', '.gm', '.gn', '.gp', '.gq', '.gr', '.gs', '.gt', '.gu', '.gw', '.gy', '.hk', '.hm', '.hn', '.hr', '.ht', '.hu', '.id', '.ie', '.il', '.im', '.in', '.io', '.iq', '.ir', '.is', '.it', '.je', '.jm', '.jo', '.jp', '.ke', '.kg', '.kh', '.ki', '.km', '.kn', '.kp', '.kr', '.kw', '.ky', '.kz', '.la', '.lb', '.lc', '.li', '.lk', '.lr', '.ls', '.lt', '.lu', '.lv', '.ly', '.ma', '.mc', '.md', '.me', '.mg', '.mh', '.mk', '.ml', '.mm', '.mn', ',mo', '.mp', '.mq', '.mr', '.ms', '.mt', '.mu', '.mv', '.mw', '.mx','.my', '.mz', '.na', '.nc', '.ne', '.nf', '.ng', '.ni', '.nl', '.no', '.np', '.nr', '.nu', '.nz', '.nz', '.om', '.pa', '.pe', '.pf', '.pg', '.ph', '.pk', '.pl', '.pm', '.pn', '.pr', '.ps', '.pt', '.pw', '.py', '.qa', '.re', '.ro', '.rs', '.ru', '.rw', '.sa', '.sb', '.sc', '.sd', '.se', '.sg', '.sh', '.si', '.sj', '.sk', '.sl', '.sm', '.sn', '.so', '.sr', '.st', '.su', '.sv', '.sy', '.sz', '.tc', '.td', '.tf', '.tg', '.th', '.tj', '.tk', '.tl', '.tm', '.tn', '.to', '.tp', '.tr', '.tt', '.tv', '.tw', '.tz', '.ua', '.ug', '.uk', '.us', '.uy', '.uz', '.va', '.vc', '.ve', '.vg', '.vi', '.vn', '.vu', '.wf', '.ws', '.ye', '.yt', '.za', '.zm', '.zw', ] # original + country (09/03/2016 -> IANA 
            for e in extensions:
                target = str(options.target + e)
                if options.verbose:
                    print "[Verbose] Trying whois to: " + target + "\n"
                try:
                    domain = whois.query(target, ignore_returncode=True) # ignore return code
                    if domain.creation_date is None: # ignore when no creation date
                        pass
                except: # ignore when fails performing query
                    pass
                else:
                    fout.write("="*22 + "\n")
                    print "-Domain: " + str(domain.name)
                    fout.write("Domain: " + str(domain.name) + "\n")
                    print "-Registrant: " + str(domain.registrar)
                    fout.write("Registrant: " + str(domain.registrar) + "\n")
                    print "-Creation date: " + str(domain.creation_date)
                    fout.write("Creation date: " + str(domain.creation_date) + "\n")
                    print "-Expiration: " + str(domain.expiration_date)
                    fout.write("Expiration: " + str(domain.expiration_date) + "\n")
                    print "-Last update: " + str(domain.last_updated) + "\n"
                    fout.write("Last update: " + str(domain.last_updated) + "\n\n")
                    if options.verbose:
                        print "[Verbose] Trying to resolve public subdomains for:", str(options.target + e), "\n"
                    url = 'https://duckduckgo.com/html/?'
                    q = 'site:.' + str(options.target + e) # ex: site:.target.com 
                    query_string = { 'q':q}
                    data = urllib.urlencode(query_string)
                    url = url + data
                    headers = {'User-Agent' : 'Crawler@alexa.com', 'Referer' : 'alexa.com'} 
                    try:
                        req = urllib2.Request(url, None, headers)
                        req_reply = urllib2.urlopen(req).read()
                    except:
                        print('\n[Error] - Your orb has been lost ...\n')
                        return
                    if req_reply == "": # no records found
                        print "- Not any record found for subdomains on search engine"
                        fout.write("- Not any record found for subdomains on search engine" + "\n")
                    regex_s = '<a class="result__url" href="(.+?)">' # regex magics
                    pattern_s = re.compile(regex_s)
                    url_links = re.findall(pattern_s, req_reply)
                    record_s = 0
                    short = "." + str(options.target + e)
                    subdomains = []
                    for url in url_links:
                        if short in url: # subdomain
                            url_s = urlparse.urlparse(url)
                            subdomain = str(url_s.hostname.split('.')[0] + "." + str(options.target + e))
                            if not 'www.' in subdomain: # parse www.
                                if not subdomain in subdomains:
                                    subdomains.append(subdomain)
                                else:
                                    pass
                            else:
                                pass 
                    for s in subdomains:
                        print "-Subdomain: " + s
                        fout.write("Subdomain: " + s + "\n")
                        record_s = record_s + 1
                    if record_s == 0:
                        print "- Not any subdomain found"
                        fout.write("- Not any subdomain found" + "\n")
                    if options.verbose:
                        print "\n[Verbose] Trying to resolve one IP for main domain ...\n"
                    try:
                        data = socket.gethostbyname_ex(domain.name) # reverse resolve ip
                        for ip in data[2]:
                            self.ip = ip
                            print "-"*22
                            fout.write("-"*22 + "\n")
                            print "-IP: " + str(ip)
                            fout.write("IP: " + str(ip) + "\n\n")
                            if options.verbose:
                                print "\n[Verbose] Trying to discover open ports on: " + str(ip) + "\n"
                            nm = nmap.PortScanner()
                            nm.scan(ip, '1-65535') # scanning ports (1-65535)
                            for host in nm.all_hosts():
                                print('-State : %s' % nm[host].state())
                            for proto in nm[host].all_protocols():
                                print('-Protocol : %s' % proto)
                                fout.write("Protocol: " + proto + "\n")
                                lport = nm[host][proto].keys()
                                lport.sort()
                                for port in lport:
                                    if str(nm[host][proto][port]['state']) == "open": # only results when open port
                                        print "  + Port:", port, "(", nm[host][proto][port]['state'], ") - ", nm[host][proto][port]['product'], nm[host][proto][port]['version'], nm[host][proto][port]['name'], nm[host][proto][port]['extrainfo'], nm[host][proto][port]['cpe']
                                        fout.write("- Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ") - " +  str(nm[host][proto][port]['product']) + str(nm[host][proto][port]['version']) + str(nm[host][proto][port]['name']) + str(nm[host][proto][port]['extrainfo']) + str(nm[host][proto][port]['cpe']) + "\n")
                    except:
                        print "\n- Not any server/machine found on that domain\n"
                        fout.write("- Not any server/machine found on that domain" + "\n")
                        pass
                    if options.verbose:
                        print "\n[Verbose] Trying to resolve DNS records ...\n"
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8', '8.8.4.4'] # google DNS resolvers
                    try:
                        answers = resolver.query(target, "A") # A records
                        for rdata in answers:
                            print "-"*22
                            fout.write("-"*22 + "\n")
                            print "-DNS [A]:", rdata
                            fout.write("-DNS [A]: " + str(rdata) + "\n\n")
                            if not (str(rdata) == self.ip): # not repeat scanning
                                if options.verbose:
                                    print "\n[Verbose] Trying to discover open ports on: " + str(rdata) + "\n"
                                nm = nmap.PortScanner()
                                nm.scan(ip, '1-65535') # scanning ports (1-65535)
                                for host in nm.all_hosts():
                                    print('-State : %s' % nm[host].state())
                                for proto in nm[host].all_protocols():
                                    print('-Protocol : %s' % proto)
                                    fout.write("Protocol: " + proto + "\n")
                                    lport = nm[host][proto].keys()
                                    lport.sort()
                                    for port in lport:
                                        if str(nm[host][proto][port]['state']) == "open": # only results when open port
                                            print "  + Port:", port, "(", nm[host][proto][port]['state'], ") - ", nm[host][proto][port]['product'], nm[host][proto][port]['version'], nm[host][proto][port]['name'], nm[host][proto][port]['extrainfo'], nm[host][proto][port]['cpe']
                                            fout.write("- Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ") - " +  str(nm[host][proto][port]['product']) + str(nm[host][proto][port]['version']) + str(nm[host][proto][port]['name']) + str(nm[host][proto][port]['extrainfo']) + str(nm[host][proto][port]['cpe']) + "\n")
                    except:
                        pass
                    try:
                        answers = resolver.query(target, "NS") # NS records
                        for rdata in answers:
                            print "-"*22
                            fout.write("-"*22 + "\n")
                            print "-DNS [NS]:", rdata
                            fout.write("-DNS [NS]: " + str(rdata) + "\n\n")
                            if options.verbose:
                                print "\n[Verbose] Trying to discover open ports on: " + str(rdata) + "\n"
                            nm = nmap.PortScanner()
                            nm.scan(ip, '1-65535') # scanning ports (1-65535)
                            for host in nm.all_hosts():
                                print('-State : %s' % nm[host].state())
                            for proto in nm[host].all_protocols():
                                print('-Protocol : %s' % proto)
                                fout.write("Protocol: " + proto + "\n")
                                lport = nm[host][proto].keys()
                                lport.sort()
                                for port in lport:
                                    if str(nm[host][proto][port]['state']) == "open": # only results when open port
                                        print "  + Port:", port, "(", nm[host][proto][port]['state'], ") - ", nm[host][proto][port]['product'], nm[host][proto][port]['version'], nm[host][proto][port]['name'], nm[host][proto][port]['extrainfo'], nm[host][proto][port]['cpe']
                                        fout.write("- Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ") - " +  str(nm[host][proto][port]['product']) + str(nm[host][proto][port]['version']) + str(nm[host][proto][port]['name']) + str(nm[host][proto][port]['extrainfo']) + str(nm[host][proto][port]['cpe']) + "\n")
                    except:
                        pass
                    try:
                        answers = resolver.query(target, "MX") # MX records
                        for rdata in answers:
                            print "-"*22
                            fout.write("-"*22 + "\n")
                            print "-DNS [MX]:", rdata
                            fout.write("-DNS [MX]: " + str(rdata) + "\n\n")
                            if options.verbose:
                                print "\n[Verbose] Trying to discover open ports on: " + str(rdata) + "\n"
                            nm = nmap.PortScanner()
                            nm.scan(ip, '1-65535') # scanning ports (1-65535)
                            for host in nm.all_hosts():
                                print('-State : %s' % nm[host].state())
                            for proto in nm[host].all_protocols():
                                print('-Protocol : %s' % proto)
                                fout.write("Protocol: " + proto + "\n")
                                lport = nm[host][proto].keys()
                                lport.sort()
                                for port in lport:
                                    if str(nm[host][proto][port]['state']) == "open": # only results when open port
                                        print "  + Port:", port, "(", nm[host][proto][port]['state'], ") - ", nm[host][proto][port]['product'], nm[host][proto][port]['version'], nm[host][proto][port]['name'], nm[host][proto][port]['extrainfo'], nm[host][proto][port]['cpe']
                                        fout.write("- Port:" + str(port) + "(" + str(nm[host][proto][port]['state']) + ") - " +  str(nm[host][proto][port]['product']) + str(nm[host][proto][port]['version']) + str(nm[host][proto][port]['name']) + str(nm[host][proto][port]['extrainfo']) + str(nm[host][proto][port]['cpe']) + "\n")
                    except:
                        pass
                    try:
                        answers = resolver.query(target, "TXT") # TXT records
                        for rdata in answers:
                            print "-"*22
                            fout.write("-"*22 + "\n")
                            print "-DNS [TXT]:", rdata
                            fout.write("-DNS [TXT]: " + str(rdata) + "\n\n")
                    except:
                        pass
                    tld_record = tld_record + 1
                    print "-"*22
                    fout.write("-"*22 + "\n")
            if tld_record == 0:
                print "- Not any valid record found on TLDs"
                fout.write("- Not any valid record found on TLDs")
            fout.close() # close .raw

        # start web-gui
        if options.gui:
            host = '0.0.0.0' # local network
            port = 6666 # local port
            try: 
                webbrowser.open('http://127.0.0.1:6666', new=1)
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
