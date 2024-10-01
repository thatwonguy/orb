#!/usr/bin/env python3
# -*- coding: utf-8 -*-"
"""
This file is part of the orb project, https://orb.03c8.net

Orb - 2016/2020 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with Orb; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import socket, threading, re, base64, os, datetime
import webbrowser, subprocess, json, sys
try:
    from urlparse import urlparse
except:
    import urllib.parse as urlparse
from .options import OrbOptions
from pprint import pprint

host = "0.0.0.0"
port = 9999

class ClientThread(threading.Thread):
    def __init__(self, ip, port, socket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.socket = socket
        self.pages = Pages()

    def run(self):
        req = self.socket.recv(2048)
        res = self.pages.get(req)
        out = "HTTP/1.0 %s\r\n" % res["code"]
        out += "Content-Type: %s\r\n\r\n" % res["ctype"]
        out += "%s" % res["html"]
        try:
            self.socket.send(out.encode('utf-8'))
        except:
            self.socket.send(out)
        self.socket.close()
        if "run" in res and len(res["run"]):
            subprocess.Popen(res["run"], shell=True)

class Pages():

    def __init__(self):
        self.options = OrbOptions()
        self.pages = {}

        self.pages["/header"] = """
<!DOCTYPE html><html>
<head>
<link rel="icon" type="image/ico" href="data:image/ico;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQIDA6sBX9r/AWrk/wFn4f8BXdb/AzR/5AAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYgKY/f8BRbL/ASBR/wEKFP8BCRH/ARtD/wE9pP8DnP3/AQAAjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZgFz6/8BM4z/AR1F/wEPH/8BBgv/AQMF/wELGf8BGTv/ATCA/wFm4v8EHkG7AAAAAAAAAAAAAAAAAAAABwF98f8BMYH/ARtD/wIMGv8DBQj/AwYK/wQHC/8DBgn/AgoU/wEYOf8BMH3/AWXh/wAAACUAAAAAAAAAAAFRx/4BMoX/ARxF/wINGv8DBgv/CRAY/w8ZKf8QGyv/ChMd/wQJD/8CCxX/ARpA/wEvfP8BUcb/AAAAAAAAAAABUMj/AR9L/wESJf8DCA//CRAY/xkwTf8uWpT/MWCd/x86X/8MFSH/BAkP/wERJP8BHUb/AT+k/wAAAAEAAAABASVe/wEVMv8BChb/BAgO/xIgMv81aKf/ZLzt/2vE8/9BgsL/FyxG/wYMEv8CCxX/ARUx/wEfTP8AAAAWAAAAAgEWNP8BDx3/AgkQ/wUJDv8VJz3/QYLC/33U+v+G2/3/UJ7Z/x02V/8IDRX/AggQ/wEPIP8BFCv/AAEBHQAAAAABDBr/AQwZ/wEHDf8EBwv/EB0s/y5Zk/9VqOH/XLHn/zhvr/8VJj3/BgsR/wIGDP8BChP/ARQw/wAAAAQAAAAAAQwY/wESJf8BBAj/AwQH/wcNE/8UJDn/I0Nt/yVHdf8XLEb/ChEZ/wMGCf8BBQj/AQsY/wEHDP8AAAAAAAAAAAISI4EBQq3/AQUI/wEDA/8CAwX/BQoP/woRGf8KEhv/BgwR/wMEB/8CAwT/AQME/wEwgv8BCxX/AAAAAAAAAAAAAAAAAUrA/wEqbf8BAQL/AAEB/wECA/8CAwT/AgME/wIDA/8AAQH/AAAA/wEdSf8EgfL/AAAAAAAAAAAAAAAAAAAAAAAAAABA4/3/AUzA/wEHDf8AAAD/AAAA/wAAAP8AAAD/AQQH/wE6n/9c6v3/AAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADiz8f97/f//AZL8/wFRyP8BTsP/AYX1/172//9dzfn/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGrK/Gml5///s+r//2/R+9MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+B8AAPAHAADgAwAAwAMAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAADAAwAA4AcAAPAPAAD+PwAA//8AAA==" />
<meta name="author" content="psy">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="content-type" content="text/xml; charset=utf-8" /> 
<title>Orb - footprinting tool</title>
<script language="javascript" src="/lib.js"></script>
"""

        self.pages["/footer"] = """</body>
</html>
"""
        self.pages["/"] = self.pages["/header"] + """<script language="javascript">function Start(){
        target=document.getElementById("target").value
        String.prototype.startsWith = function(prefix){
        return this.indexOf(prefix) === 0;
        }
        if(target!=""){
             if (document.getElementById("massive").checked){
                document.getElementById("massive").value = "on";
             } else {
                document.getElementById("massive").value = "off";
             }
             massive = document.getElementById("massive").value
             extens =document.getElementById("extens").value
             engineloc=document.getElementById("engineloc").value
             if (document.getElementById("json").checked){
                document.getElementById("json").value = "on";
             } else {
                document.getElementById("json").value = "off";
             }
             json = document.getElementById("json").value
             if (document.getElementById("nopublic").checked){
                document.getElementById("nopublic").value = "on";
             } else {
                document.getElementById("nopublic").value = "off";
             }
             nopublic = document.getElementById("nopublic").value
             if (document.getElementById("nowhois").checked){
                document.getElementById("nowhois").value = "on";
             } else {
                document.getElementById("nowhois").value = "off";
             }
             nowhois = document.getElementById("nowhois").value
             if (document.getElementById("nosubs").checked){
                document.getElementById("nosubs").value = "on";
             } else {
                document.getElementById("nosubs").value = "off";
             }
             nosubs = document.getElementById("nosubs").value
             if (document.getElementById("nodns").checked){
                document.getElementById("nodns").value = "on";
             } else {
                document.getElementById("nodns").value = "off";
             }
             nodns = document.getElementById("nodns").value
             if (document.getElementById("noscanner").checked){
                document.getElementById("noscanner").value = "on";
             } else {
                document.getElementById("noscanner").value = "off";
             }
             noscanner = document.getElementById("noscanner").value
             if (document.getElementById("noscandns").checked){
                document.getElementById("noscandns").value = "on";
             } else {
                document.getElementById("noscandns").value = "off";
             }
             noscandns = document.getElementById("noscandns").value
             if (document.getElementById("noscanns").checked){
                document.getElementById("noscanns").value = "on";
             } else {
                document.getElementById("noscanns").value = "off";
             }
             noscanns = document.getElementById("noscanns").value
             if (document.getElementById("noscanmx").checked){
                document.getElementById("noscanmx").value = "on";
             } else {
                document.getElementById("noscanmx").value = "off";
             }
             noscanmx = document.getElementById("noscanmx").value
             scanports =document.getElementById("scanports").value
             if (document.getElementById("onlytcp").checked){
                document.getElementById("onlytcp").value = "on";
             } else {
                document.getElementById("onlytcp").value = "off";
             }
             onlytcp = document.getElementById("onlytcp").value
             if (document.getElementById("nobanner").checked){
                document.getElementById("nobanner").value = "on";
             } else {
                document.getElementById("nobanner").value = "off";
             }
             nobanner = document.getElementById("nobanner").value
             if (document.getElementById("cve").checked){
                document.getElementById("cve").value = "on";
             } else {
                document.getElementById("cve").value = "off";
             }
             cve = document.getElementById("cve").value
             if (document.getElementById("cvs").checked){
                document.getElementById("cvs").value = "on";
             } else {
                document.getElementById("cvs").value = "off";
             }
             cvs = document.getElementById("cvs").value
             params="target="+escape(target)+"&massive="+escape(massive)+"&extens="+escape(extens)+"&engineloc="+escape(engineloc)+"&nopublic="+escape(nopublic)+"&nowhois="+escape(nowhois)+"&nosubs="+escape(nosubs)+"&nodns="+escape(nodns)+"&noscanner="+escape(noscanner)+"&noscandns="+escape(noscandns)+"&noscanns="+escape(noscanns)+"&noscanmx="+escape(noscanmx)+"&scanports="+escape(scanports)+"&onlytcp="+escape(onlytcp)+"&nobanner="+escape(nobanner)+"&cve="+escape(cve)+"&cvs="+escape(cvs)+"&json="+escape(json)
        }else{
          window.alert("You need to enter something... (ex: dell)");
          return
        }
        runCommandX("cmd_spell", params)
}
</script><script>loadXMLDoc()</script><script type='text/javascript'>var index = 0;var text = 'Welcome to...        Orb !!!';function type(){document.getElementById('screen').innerHTML += text.charAt(index);index += 1;var t = setTimeout('type()',120);}</script><script type='text/javascript'>
function show(one) {
      var nb = document.getElementsByTagName("div");
            for(var x=0; x<nb.length; x++) {
                  name = nb[x].getAttribute("class");
                  if (name == 'nb') {
                        if (nb[x].id == one) {
                        nb[x].style.display = 'block';
                  }
                  else {
                        nb[x].style.display = 'none';
                  }
            }
      }
}
</script><script type='text/javascript'>
function checkNobanner(){
  if (document.getElementById("nobanner").checked == true){
      document.getElementById("cve").checked = true;
      document.getElementById("cvs").checked = true;
}}
</script><script type='text/javascript'>
function checkNoscanner(){
  if (document.getElementById("noscanner").checked == true){
      document.getElementById("noscandns").checked = true;
      document.getElementById("noscanns").checked = true;
      document.getElementById("noscanmx").checked = true;
}}
</script><script type='text/javascript'>
function checkBoth(){
  if (document.getElementById("both").checked == true){
      document.getElementById("noscanner").checked = false;
      document.getElementById("nobanner").checked = false;
      document.getElementById("cve").checked = false;
      document.getElementById("cvs").checked = false;
      document.getElementById("nodns").checked = false;
      document.getElementById("noscandns").checked = false;
      document.getElementById("noscanns").checked = false;
      document.getElementById("noscanmx").checked = false;
      document.getElementById("nopublic").checked = false;
      document.getElementById("nowhois").checked = false;
      document.getElementById("nosubs").checked = false;
             }}
</script><script type='text/javascript'>
function checkPassive(){
  if (document.getElementById("passive").checked == true){
      document.getElementById("noscanner").checked = true;
      document.getElementById("nobanner").checked = true;
      document.getElementById("cve").checked = true;
      document.getElementById("cvs").checked = true;
      document.getElementById("nodns").checked = true;
      document.getElementById("noscandns").checked = true;
      document.getElementById("noscanns").checked = true;
      document.getElementById("noscanmx").checked = true;
      document.getElementById("nopublic").checked = false;
      document.getElementById("nowhois").checked = false;
      document.getElementById("nosubs").checked = false;
             }}
</script><script type='text/javascript'>
function checkActive(){
  if (document.getElementById("active").checked == true){
      document.getElementById("nopublic").checked = true;
      document.getElementById("nowhois").checked = true;
      document.getElementById("nosubs").checked = true;
      document.getElementById("noscanner").checked = false;
      document.getElementById("noscandns").checked = false;
      document.getElementById("noscanns").checked = false;
      document.getElementById("noscanmx").checked = false;
      document.getElementById("nobanner").checked = false;
      document.getElementById("cve").checked = false;
      document.getElementById("cvs").checked = false;
      document.getElementById("nodns").checked = false;
             }}
</script>
</head>
<body onload='type()' bgcolor="black" text="orange" style="monospace;" ><center><table><tr><td><pre>
                             #Y
                           U#@#%$
                        ...........
                   ....................
                ...,,,,,,,,,,,,,,,,,,,....                  
              ..,,,,,,,,,,,,,,,,,,,,,,,,,,...              
           ..,,,,,,,,,,,,,,,,,,,,,,,...,,,,,,..            
         .,,,,,,,,,,.........................,,,,.         
       .,,,,...............................   ..,*,        
      .,,,...................................   .,*/.      
    .,,....................................       ./#(.    
   .,......................................        .(#(.   
  .,,...................................            .*#/.  
 .*,.................................                 *#(  
 ,/,...............................                   .(#, 
.#/,.............................                     *#(( 
.#/,.............................                     **/(.
 (/*...........................                      .*/// 
 /(*.........................                       .,**/* 
 ,((,........................                       ,,*//. 
  ((*......................                        .,,*/*  
  .*(,.....................                        ,,,*,.  
    //*...................                       ..,,,,    
     /(,     .............                      .,,,,,     
      .**.     ...............               ...,,,,.      
        ,*,    ...............            ....,,,,,        
          **,    ............................,,,,.         
        ,*(#(/,.   .......................,,,*###/,        
       ./##(((((/*,,..................,,,,/((((((//,       
       **,*%%%((((#(/***,,,,,,,,,,,,,,*(###((###((#/       
      .#%%%%%%%#((((*******,,,,,,,,,,,,/(((((#%&%%%#.      
      ./##%/*,/((***,     ..,....      ./(/(#(,,*(#/       
      .,,,.,**/(%#(,                     .**///*.,,.       
      .,,,*,. ,***,                          .*,,,..       
      .,*/*.                                   .,*,,.      
    ,#(/,,,                                     .,*(#(,    
</pre></td><td><table border="1" cellpadding="10" cellspacing="10"><tr><td> <div><a id="mH1" href="javascript:show('nb1');" style="text-decoration: none;" >+ Info</a></div>
<div><a id="mH2" href="javascript:show('nb2');" style="text-decoration: none;" >+ Contact</a></div>
</td><td><i><h3><div id='screen'></div></h3></i><div class="nb" id="nb1" style="display: none;"><pre>This is a massive <a href="https://en.wikipedia.org/wiki/Footprinting" target="_blank">footprinting</a> tool. It will 
use <u>automated</u> gathering methods to provides
you information about a target.

  <a href="https://orb.03c8.net" target="_blank">Website</a> | <a href="https://code.03c8.net/epsylon/orb" target="_blank">Code</a> | <a href="https://github.com/epsylon/orb" target="_blank">Mirror</a> | <a href="https://blockchain.info/address/19aXfJtoYJUoXEZtjNwsah2JKN9CK5Pcjw" target="_blank">Donate</a> 

---------

<div><a id="mH0" href="javascript:show('nb0');" style="text-decoration: none;" >Close()</a></div><div class="nb" id="nb0" style="display: none;"></div></pre></div><div class="nb" id="nb2" style="display: none;"><pre>If you want to contribute to development, 
reporting a bug, providing a patch, 
commenting on the code, making a donation
or simply need to find help to run it, 
please drop me an <a href="mailto:epsylon@riseup.net">e-mail</a>.

---------

<div><a id="mH0" href="javascript:show('nb0');" style="text-decoration: none;" >Close()</a></div><div class="nb" id="nb0" style="display: none;"></div></pre></div></td></tr></table><br />
<form method='GET'><fieldset><table border="0" cellpadding="5" cellspacing="5"><tr><td> TLD extension(s):</td><td><input type="text" id="extens" name="extens" size="20" value=".com,.net" title="set extensions manually (ex: '.com,.net,.es')"></td></tr></table><br /><table border="1" cellpadding="5" cellspacing="5"><tr><td> Methods:</td><td><input type="radio" name="method" title="use both -active/passive- methods" id="both" value="both" onclick="checkBoth()" checked> Both</td><td><input type="radio" name="method" title="use ONLY -passive- methods" id="passive" value="passive" onclick="checkPassive()"> Passive</td><td><input type="radio" name="method" title="use ONLY -active- methods" id="active" value="active" onclick="checkActive()"> Active</td></tr></table><br><table border="1" cellpadding="5" cellspacing="5"><tr><td>Extra:</td><td><div><a id="mH3" href="javascript:show('nb3');" style="text-decoration: none;" >+ Config</a></div></td><td><input type="checkbox" id="autoscrolling" title="active auto-scrolling"/> Auto-Scroll</td><td><input type="checkbox" id="json" title="generate json report"/> Json</td></tr></table><br><table><tr><td>TARGET: <input type="text" name="target" id="target" size="26" placeholder="microsoft, facebook ..." title="start complete footprinting on this target" required></td></tr></table><br><div class="nb" id="nb3" style="display: none;"><table border="1" cellpadding="5" cellspacing="5"><tr><td><input type="checkbox" id="nopublic" name="nopublic" title="disable search for public records"/> No-Public</td><td>Engine loc: <input type="text" id="engineloc" name="engineloc" size="2" title="set location for search engine (ex: 'fr')"></td><td><input type="checkbox" id="massive" name="massive" title="search massively using all search engines (default: Yahoo)" checked/> Massive</td></tr><tr><td><input type="checkbox" id="nowhois" name="nowhois" title="disable extract whois information"/> No-Whois</td><td><input type="checkbox" id="nosubs" name="nosubs" title="disable try to discover subdomains"/> No-Subs</td><td><input type="checkbox" id="nodns" name="nodns" title="disable try to discover DNS records"/> No-DNS</td></tr><tr><td><input type="checkbox" id="noscanner" name="noscanner" title="disable scanner" onclick="checkNoscanner()"/> No-Scanner</td><td>Ports: <input type="text" size="6" id="scanports" name="scanports" value="1-65535" title="set range of ports to scan"></td><td><input type="checkbox" name="onlytcp" id="onlytcp" title="set scanning protocol to only TCP"/> Only-TCP</td></tr><td><input type="checkbox" id="noscandns" name="noscandns" title="disable scan DNS machines"/> No-Scan-DNS</td><td><input type="checkbox" id="noscanns" name="noscanns" title="disable scan NS records"/> No-Scan-NS</td><td><input type="checkbox" id="noscanmx" name="noscanmx" title="disable scan MX records"/> No-Scan-MX</td></tr><tr><td><input type="checkbox" id="nobanner" name="nobanner" title="disable extract banners from services" onclick="checkNobanner()"/> No-Banner</td><td><input type="checkbox" id="cve" name="cve" title="disable extract vulnerabilities from CVE"/> No-CVE</td><td><input type="checkbox" id="cvs" name="cvs" title="disable extract CVS description"/> No-CVS</td></tr></table><div><a id="mH0" href="javascript:show('nb0');" style="text-decoration: none;" ><pre>Close()</pre></a></div><div class="nb" id="nb0" style="display: none;"></div></div></td></tr></table></fieldset></form><button title="Nihil Sine Chaos!!" onClick=Start()>Spell!</button><hr></center><div id="cmdOut"></div>""" + self.pages["/footer"]

        self.pages["/lib.js"] = """function loadXMLDoc() {
        var xmlhttp;
        if (window.XMLHttpRequest) {
                // code for IE7+, Firefox, Chrome, Opera, Safari
                xmlhttp = new XMLHttpRequest();
        } else {
                // code for IE6, IE5
                xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
        }
        xmlhttp.onreadystatechange = function() {
                if (xmlhttp.readyState == 4 ) {
                   if(xmlhttp.status == 200){
                           document.getElementById("cmdOut").innerHTML = xmlhttp.responseText;
                           setTimeout("loadXMLDoc()", 3000); 
                   }
                }
        }
        xmlhttp.send();
	}

function runCommandX(cmd,params) {
        var xmlhttp;
        if (window.XMLHttpRequest) {
                // code for IE7+, Firefox, Chrome, Opera, Safari
                xmlhttp = new XMLHttpRequest();
        } else {
                // code for IE6, IE5
                xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
        }
        xmlhttp.onreadystatechange = function() {
                if (xmlhttp.readyState == 4 ) {
                   if(xmlhttp.status == 200){
								if(cmd.indexOf("?")!=-1){
									s=cmd.split("?")
									cmd=s[0]
									params=s[1]
								}
                                document.getElementById("cmdOut").innerHTML = xmlhttp.responseText;
                                if (document.getElementById("autoscrolling").checked){
                                     document.getElementById("cmdOut").scrollIntoView();
                                }
                                newcmd=cmd
                                if(newcmd=="cmd_null"){ 
                                    return;
                                } else {
                                if(newcmd=="cmd_spell") newcmd=newcmd+"_update"
                                setTimeout(function(){runCommandX(newcmd,params)}, 3000);
								return;}
                   }
                }
        }
		if(typeof params != "undefined") cmd=cmd+"?"+params
        xmlhttp.open("GET", cmd, true);
        xmlhttp.send();
}

"""
    def buildGetParams(self, request):
        params = {}
        try:
            path = re.findall(r"^GET ([^\s]+)", request)

        except:
            path = re.findall(r"^GET ([^\s]+)", request.decode('utf-8'))
        if path:
            path = path[0]
            start = path.find("?")
            if start != -1:
                for param in path[start+1:].split("&"):
                    f = param.split("=")
                    if len(f) == 2:
                        var = f[0]
                        value = f[1]
                        value = value.replace("+", " ")
                        value = urlparse.unquote(value)
                        params[var] = value
        return params

    def get(self, request):
        cmd_options = ""
        runcmd = ""
        try:
            res = re.findall(r"^GET ([^\s]+)", request)
        except:
            res = re.findall(r"^GET ([^\s]+)", request.decode('utf-8'))
        if res is None or len(res)==0:
            return
        pGet = {}
        page = res[0]
        paramStart = page.find("?")
        if paramStart != -1:
            page = page[:paramStart]
            pGet = self.buildGetParams(request)
        if page == "/cmd_spell":
            self.pages["/cmd_spell"] = "<pre>Waiting for 'orb' to return with data ...</pre>"
            if pGet["massive"] == "on": # --sa
                cmd_options+= " --sa"
            if pGet["extens"]: # --ext=
                cmd_options+= " --ext="+pGet["extens"]
            if pGet["engineloc"] != "": # --ext=
                cmd_options+= " --se-ext="+pGet["engineloc"]
            if pGet["json"] == "on": # --json=target_datetime.json
                namefile = pGet["target"] + ".json"
                cmd_options+= " --json="+str(namefile)
            if pGet["nopublic"] == "on": # --no-public
                cmd_options+= " --no-public"
            if pGet["nowhois"] == "on": # --no-whois
                cmd_options+= " --no-whois"
            if pGet["nosubs"] == "on": # --no-subs
                cmd_options+= " --no-subs"
            if pGet["nodns"] == "on": # --no-dns
                cmd_options+= " --no-dns"
            if pGet["noscanner"] == "on": # --no-scanner
                cmd_options+= " --no-scanner"
            if pGet["noscandns"] == "on": # --no-scan-dns
                cmd_options+= " --no-scan-dns"
            if pGet["noscanns"] == "on": # --no-scan-ns
                cmd_options+= " --no-scan-ns"
            if pGet["noscanmx"] == "on": # --no-scan-mx
                cmd_options+= " --no-scan-mx"
            if pGet["scanports"]: # --scan-ports=
                cmd_options+= " --scan-ports="+pGet["scanports"]
            if pGet["onlytcp"] == "on": # --scan-tcp
                cmd_options+= " --scan-tcp"
            if pGet["nobanner"] == "on": # --no-banner
                cmd_options+= " --no-banner"
            if pGet["cve"] == "on": # --no-cve
                cmd_options+= " --no-cve"
            if pGet["cvs"] == "on": # --no-cvs
                cmd_options+= " --no-cvs"
            runcmd = "(python -i orb --spell '"+pGet["target"]+"'"+ cmd_options + "|tee /tmp/out) &"
        if page == "/cmd_spell_update":
            if not os.path.exists('/tmp/out'):
                open('/tmp/out', 'w').close()
            with open('/tmp/out', 'r') as f:
                self.pages["/cmd_spell_update"] = "<pre>"+f.read()+"<pre>"
        ctype = "text/html"
        if page.find(".js") != -1:
            ctype = "application/javascript"
        elif page.find(".txt") != -1:
            ctype = "text/plain"
        elif page.find(".ico") != -1:
            ctype = "image/x-icon"
        elif page.find(".png") != -1:
            ctype = "image/png"
        if page in self.pages:
            return dict(run=runcmd, code="200 OK", html=self.pages[page], ctype=ctype)
        return dict(run=runcmd, code="404 Error", html="404 Error<br><br>Page not found...", ctype=ctype)

class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
            self.process = subprocess.Popen(self.cmd, shell=True)
        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()

if __name__ == "__main__":
    webbrowser.open('http://127.0.0.1:9999', new=1)
    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind((host, port))
    while True:
        tcpsock.listen(4)
        (clientsock, (ip, c_port)) = tcpsock.accept()
        newthread = ClientThread(ip, c_port, clientsock)
        newthread.start()
