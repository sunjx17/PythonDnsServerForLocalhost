import requests
import threading
def dns_get_google(host):
    proxy={"https": "socks5://127.0.0.1:1088"}
    try:
        url='https://dns.google.com/resolve'
        param={'name':host,'type':'a'}
        P_get=requests.get(url,params=param,proxies=proxy,timeout=3).json()
        if P_get['Status']==0:
            print('get ip from google(http)')
            ans=P_get["Answer"]
            for i in range(len(ans)):
                if ans[i]['type']==1:
                    #print(ans[i]['data'])
                    return ans[i]['data'],ans[i]['TTL']
            return False
        else:
            print('no dns from google')
            return False
    except Exception:
        print('get ip fail from google')
        return False
def dns_get_cloudfare(host):
    try:
        url='https://1.1.1.1/dns-query'
        param={'ct':'application/dns-json','name':host,'type':'A'}
        P_get=requests.get(url,params=param,timeout=3).json()
        if P_get['Status']==0:
            print('get ip from cloudfare(http)')
            ans=P_get["Answer"]
            for i in range(len(ans)):
                if ans[i]['type']==1:
                    #print(ans[i]['data'])
                    return ans[i]['data'],ans[i]['TTL']
            return False
        else:
            print('no dns from cloudfare')
            return False
    except Exception:
        print('get ip fail from cloudfare')
        return False
def dns_get_tencent(host):
    try:
        url='http://119.29.29.29/d'
        param={'dn':host}
        P_get=requests.get(url,params=param,timeout=3)
        iplist=P_get.text.split(';')
        addrs_len=len(iplist[0].split('.'))
        if addrs_len==4:
            print('get ip from 119.29.29.29(http)')
            return iplist[0],33060
        else:
            print('no dns from tencent')
            return False
    except Exception:
        print('get ip fail from tencent')
        return False
int0=0
def httpdns(name):
    global int0
    int0+=1
    int0%=3
    if int0==0:
        return dns_get_google(name) or dns_get_tencent(name) or dns_get_cloudfare(name) or (False,False)
    elif int0==1:
        return dns_get_tencent(name) or dns_get_cloudfare(name) or dns_get_google(name) or (False,False)
    else:
        return dns_get_cloudfare(name) or dns_get_tencent(name) or dns_get_google(name) or (False,False)
