from dns_class import DNSserver,DNSblack
import re
def blist(host):
	b=[".vivo.",".microsoft.",".windowsupdate.",".msftncsi.",".wns.windows."]
	for i in range(len(b)):
		if re.search(b[i],host):
			print("blocked ",b[i])
			return True
	return False

DNSserver.add_name('21o9v11137.imwork.net', '192.168.43.24',3600*24*356)    # add a A record
DNSblack.add_func(blist)
DNSserver.start()