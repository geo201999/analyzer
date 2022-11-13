import json
from ipaddress import ip_address
import requests
from requests.auth import HTTPBasicAuth

def cveCheck(api_keys):
    print('')
    try:
    
        cve_key= api_keys['cve-key']
        headers = {'Accept': 'application/json'}
        auth = HTTPBasicAuth('apikey', cve_key)

        a_file = open("CVE.txt", "r")
        lines = a_file.read()
        list_of_lists = lines.splitlines()
        a_file.close()
        print('ANALYZING THE CVE  ...... ', list_of_lists, '\n')

        for i in range (len(list_of_lists)):
            url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+list_of_lists[i]
            response = requests.get(url, headers=headers, auth=auth)
            cvedata=response.json()
            results=cvedata['totalResults']
            if response.status_code == 200:
                if (int(results) > 0 ):
                    print ("INFO CVE :  ---> " + list_of_lists[i]+ " : ")
                    
                    resultado = cvedata['vulnerabilities']

                    for j in resultado:

                        print('Vuln ID: ',j['cve']['id'])
                        print('published: ',j['cve']['published'])

                        print('Description: ',j['cve']['descriptions'][0]['value'])
                        metricas = j['cve']['metrics']['cvssMetricV31']

                        for m in metricas:
                            print("Impact score :",m['impactScore'])
                            print("Attack complexity :",m['cvssData']['attackComplexity'])
                            print("Base score :",m['cvssData']['baseScore'])
                        print('Tags: ',j['cve']['references'][0]['tags'])
                    print ('For Further Info Check : ' + "https://otx.alienvault.com/indicator/file/"+list_of_lists[i])
                    print('\n')

                else:
                    print ('THE CVE IS NOT IN THE DATABASE')    

            else:
                print("Failed for HASH "+ list_of_lists[i])
    except:
        print("PLEASE CHECK THE FILE (ERROR) ")
                    

                


                    
           