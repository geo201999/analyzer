
import json
from ipaddress import ip_address
import requests
from requests.auth import HTTPBasicAuth


def hashCall(api_keys):
    try:

        headers = api_keys['vtotal']
        apiKey= api_keys ['X-forcekey']
        password= api_keys['xforcepassw']
        alien= api_keys['alien-key']

        a_file = open("Hash.txt", "r")
        lines = a_file.read()
        list_of_lists = lines.splitlines()
        a_file.close()
        print('ANALYZING THE HASHES  ...... ', list_of_lists, '\n')

        for i in range (len(list_of_lists)):
                       
            response = requests.get("https://www.virustotal.com/api/v3/files/"+list_of_lists[i], headers=headers)
            if response.status_code == 200:
                vinfo=response.json()
                print ("Virus Total HASH Reputation  ---> " + list_of_lists[i]+ " : ")
                print("Possible Name:", vinfo['data']['attributes']['meaningful_name'])
                print("Type Description:", vinfo['data']['attributes']['type_description'])
                print(vinfo['data']['attributes']['last_analysis_stats']['harmless'],':vendors detected this as harmless')
                print(vinfo['data']['attributes']['last_analysis_stats']['malicious'],':vendors detected this as malicious')
                print(vinfo['data']['attributes']['last_analysis_stats']['suspicious'],':vendors detected this as suspicious')
                print(vinfo['data']['attributes']['last_analysis_stats']['undetected'],':vendors detected this as undetected')
                print("Reputation:", vinfo['data']['attributes']['reputation'])

                print (' ')
                print ('For Further Info Check : ' + "https://www.virustotal.com/gui/file/"+list_of_lists[i])

                print('\n')
            else:
                print("Failed for HASH "+ list_of_lists[i])
            
            if response.status_code==200:
                data = requests.get('https://exchange.xforce.ibmcloud.com/api/malware/'+list_of_lists[i], auth = HTTPBasicAuth(apiKey, password))
                data = data.json()
                print ("X-Force HASH reputation  ---> " + list_of_lists[i]+ " : ")
                print("RISK: ",data['malware']['risk'])
                print("Malware type: ",data['malware']['origins']['external']['malwareType'])
                print("First seen: ",data['malware']['origins']['external']['firstSeen'])
                print("Last seen: ",data['malware']['origins']['external']['lastSeen'])
                print("Hash Type: ",data['malware']['type'])
                print("Family: ",data['malware']['origins']['external']['family'])

                print(" ")
                print ('For Further Info Check : ' + "https://exchange.xforce.ibmcloud.com/malware/"+list_of_lists[i])
                print('\n')

            else:
                print("Failed for HASH "+ list_of_lists[i])
                
            if response.status_code==200:
                aliendata = requests.get('https://otx.alienvault.com/api/v1/indicators/file/'+list_of_lists[i]+'/analysis', alien)
                aliendata = aliendata.json()
                print ("AlienVault HASH reputation  ---> " + list_of_lists[i]+ " : ")
                print ('File Class: ',aliendata['analysis']['info']['results']['file_class'])
                print ('File Type: ',aliendata['analysis']['info']['results']['file_type'])
                print ('File class: ',aliendata['analysis']['info']['results']['sha1'])
                print(vinfo['data']['attributes']['last_analysis_stats']['malicious'],':vendors detected this as malicious')

                print(" ")
                print ('For Further Info Check : ' + "https://otx.alienvault.com/indicator/file/"+list_of_lists[i])
                print('\n')

            else:
                print("Failed for HASH "+ list_of_lists[i])
      


    except(ValueError):

        print ("ERROR PLEASE DO IT AGAIN") 