#!/usr/bin/env python 
# -*- coding: utf-8 -*-"
"""
This file is part of the orb project, http://orb.03c8.net

Orb - 2016 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with RedSquat; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import socket, threading, re, base64, os
import webbrowser, subprocess, urllib, json, sys
from options import OrbOptions
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
<link rel="icon" type="image/png" href="/favicon.ico" />
<meta name="author" content="psy">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="content-type" content="text/xml; charset=utf-8" /> 
<title>Orb - footprinting tool</title>
<script language="javascript" src="/lib.js"></script>
"""

        self.pages["/footer"] = """</body>
</html>
"""
        self.pages["/favicon.ico"] = base64.b64decode("AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQIDA6sBX9r/AWrk/wFn4f8BXdb/AzR/5AAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYgKY/f8BRbL/ASBR/wEKFP8BCRH/ARtD/wE9pP8DnP3/AQAAjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZgFz6/8BM4z/AR1F/wEPH/8BBgv/AQMF/wELGf8BGTv/ATCA/wFm4v8EHkG7AAAAAAAAAAAAAAAAAAAABwF98f8BMYH/ARtD/wIMGv8DBQj/AwYK/wQHC/8DBgn/AgoU/wEYOf8BMH3/AWXh/wAAACUAAAAAAAAAAAFRx/4BMoX/ARxF/wINGv8DBgv/CRAY/w8ZKf8QGyv/ChMd/wQJD/8CCxX/ARpA/wEvfP8BUcb/AAAAAAAAAAABUMj/AR9L/wESJf8DCA//CRAY/xkwTf8uWpT/MWCd/x86X/8MFSH/BAkP/wERJP8BHUb/AT+k/wAAAAEAAAABASVe/wEVMv8BChb/BAgO/xIgMv81aKf/ZLzt/2vE8/9BgsL/FyxG/wYMEv8CCxX/ARUx/wEfTP8AAAAWAAAAAgEWNP8BDx3/AgkQ/wUJDv8VJz3/QYLC/33U+v+G2/3/UJ7Z/x02V/8IDRX/AggQ/wEPIP8BFCv/AAEBHQAAAAABDBr/AQwZ/wEHDf8EBwv/EB0s/y5Zk/9VqOH/XLHn/zhvr/8VJj3/BgsR/wIGDP8BChP/ARQw/wAAAAQAAAAAAQwY/wESJf8BBAj/AwQH/wcNE/8UJDn/I0Nt/yVHdf8XLEb/ChEZ/wMGCf8BBQj/AQsY/wEHDP8AAAAAAAAAAAISI4EBQq3/AQUI/wEDA/8CAwX/BQoP/woRGf8KEhv/BgwR/wMEB/8CAwT/AQME/wEwgv8BCxX/AAAAAAAAAAAAAAAAAUrA/wEqbf8BAQL/AAEB/wECA/8CAwT/AgME/wIDA/8AAQH/AAAA/wEdSf8EgfL/AAAAAAAAAAAAAAAAAAAAAAAAAABA4/3/AUzA/wEHDf8AAAD/AAAA/wAAAP8AAAD/AQQH/wE6n/9c6v3/AAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADiz8f97/f//AZL8/wFRyP8BTsP/AYX1/172//9dzfn/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGrK/Gml5///s+r//2/R+9MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+B8AAPAHAADgAwAAwAMAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAADAAwAA4AcAAPAPAAD+PwAA//8AAA==")

        self.pages["/"] = self.pages["/header"] + """<script language="javascript">function Start(){
        target=document.getElementById("target").value
        String.prototype.startsWith = function(prefix){
        return this.indexOf(prefix) === 0;
        }
        if(target!=""){
        params="target="+escape(target)
        runCommandX("cmd_spell", params)
        }else{
          window.alert("You need to enter something... (ex: dell)");
          return
        }
}
</script><script>loadXMLDoc()</script></head>
<body bgcolor="black" text="orange" style="monospace;" ><center><pre>
<a href="http://orb.03c8.net" target="_blank">http://orb.03c8.net</a>
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
 (*,...............................                   ,((/ 
.#/,.............................                     *#(( 
.#/,.............................                     **/(.
.#(*............................                     .*///.
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
  */((((**.                                     .**(//((,  
  ,//*,.                                           .*//,.  
</pre><hr>
Target: <input type="text" name="target" id="target" size="22" placeholder="microsoft, facebook ..." required> <button onClick=Start()>Spell!</button><input type="checkbox" id="autoscrolling" checked/> auto-scroll<hr> </center>
<div id="cmdOut"></div>
""" + self.pages["/footer"]

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
		  		if(newcmd.match(/update/) && 
				(
			  xmlhttp.responseText.match(/destroyed/)
										) 
				) return;
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
        path = re.findall("^GET ([^\s]+)", request)
        if path:
            path = path[0]
            start = path.find("?")
            if start != -1:
                if path[start+1:start+7] == "target":
                    params['target']=path[start+8:]
                    return params
                for param in path[start+1:].split("&"):
                    f = param.split("=")
                    if len(f) == 2:
                        var = f[0]
                        value = f[1]
                        value = value.replace("+", " ")
                        value = urllib.unquote(value)
                        params[var] = value
        return params

    def get(self, request):
        cmd_options = ""
        runcmd = ""
        res = re.findall("^GET ([^\s]+)", request)
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
            runcmd = "(python -i orb --spell '"+pGet["target"]+"' "+ cmd_options + "|tee /tmp/out) &"
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
    webbrowser.open('http://127.0.0.1:6666', new=1)
    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind((host, port))
    while True:
        tcpsock.listen(4)
        (clientsock, (ip, c_port)) = tcpsock.accept()
        newthread = ClientThread(ip, c_port, clientsock)
        newthread.start()
