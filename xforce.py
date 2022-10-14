import requests
from requests.auth import HTTPBasicAuth
from ipaddress import ip_address


def ipCheck():
        ### X-Force ApiKey ###
        apiKey= 'a1f4c674-534f-49f9-b9b3-f54192e840d1'
        password= 'd5bf87b8-3fa3-4282-a0c6-400cf6d67fd3'

        ###Virus Total Headers###
        headers = {"accept": "application/json", "x-apikey": "e0f6e71ffffcb629f728ead19aa68751f0def592f76265c72f41f6da2b28d49a"}

        ### Fraud guard ###
        key= '9FCLGakf8PxkishQ'
        fpassword= 'TDTAsifOn2iS5fI3'

        listPrivateIps = []
        a_file = open("IPs.txt", "r")
        lines = a_file.read()
        list_of_lists = lines.splitlines()
        a_file.close()

        print('ANALYZING IPS  ...... ', list_of_lists, '\n')

        for i in range (len(list_of_lists)):
                checkIP = list_of_lists[i]
                ipIs = IPAddress(checkIP)
                if ipIs == 'Public':
                        data = requests.get('https://exchange.xforce.ibmcloud.com/api/ipr/'+list_of_lists[i], auth = HTTPBasicAuth( apiKey, password))
                        if data.status_code == 200:
                                data = data.json()
                                location = data['geo']
                                score = data['score']
                                cat= data['categoryDescriptions']
                                cats = data['cats']
                                tag= data['tags']
                                reason = data['reasonDescription']

                                print ("X-FORCE IP Reputation  ---> " + list_of_lists[i]+ " : ")

                                print("Score Risk :",score)

                                if score == 1:
                                        print ("The Ip is not malicious")
                                elif score >= 2 and score <= 5:
                                        print ("The IP is suspicious, please check")
                                else:
                                        print("The IP is malicious, please block it or add it to the black list")
        
                                print ('Location : ',location)
                                print ('Categorization : ', cats, cat)
                                print ('Tags : ', tag)
                                print ('Reason Description : ', reason)
                                print ('For Further Info Check : ' + "https://exchange.xforce.ibmcloud.com/ip/"+list_of_lists[i])

                                print('\n')
                        else:
                                print("Failed for IP "+ list_of_lists[x]) 

                        fraudData = requests.get('https://api.fraudguard.io/ip/'+list_of_lists[i], auth = HTTPBasicAuth(key, fpassword))
                        if fraudData.status_code == 200:
                                fraudInfo=fraudData.json()
                                print ("Fraud Guard IP Reputation  ---> " + list_of_lists[i]+ " : ")
                                print('Location : ',fraudInfo['country'])
                                print('Threat : ',fraudInfo['threat'])
                                print('Discover date : ',fraudInfo['discover_date'])
                                print('Risk Level : ',fraudInfo['risk_level'])
                                print ('For Further Info Check : ' + "https://fraudguard.io/?ip="+list_of_lists[i])                                        
                                print('\n')
                        else:
                                print("Failed for IP "+ list_of_lists[x]) 
                        
                        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+list_of_lists[i], headers=headers)
                        if response.status_code == 200:
                                vinfo=response.json()
                                
                                print ("Virus Total IP Reputation  ---> " + list_of_lists[i]+ " : ")
                                print(vinfo['data']['attributes']['last_analysis_stats']['harmless'],':vendors detected this as harmless')
                                print(vinfo['data']['attributes']['last_analysis_stats']['malicious'],':vendors detected this as malicious')
                                print(vinfo['data']['attributes']['last_analysis_stats']['suspicious'],':vendors detected this as suspicious')
                                print(vinfo['data']['attributes']['last_analysis_stats']['undetected'],':vendors detected this as undetected')
                                
                                print (' ')

                                print('Whois : ')
                                print(vinfo['data']['attributes']['whois'])
                                print ('For Further Info Check : ' + "https://www.virustotal.com/gui/ip-address/"+list_of_lists[i])                                        



                                print('\n')
                        else:
                                print("Failed for IP "+ list_of_lists[i])
                                
                else: 
                        if ipIs == 'Private':
                                print("PRIVATE  IP -----> " , list_of_lists[i])

                        elif ipIs=='APIPA':

                                print("APIPA    IP -----> " , list_of_lists[i])


                        elif ipIs=='loopback':
                                print("LOOPBACK IP -----> " , list_of_lists[i])


                        elif ipIs=='Default IP':
                                print("Default  IP -----> " , list_of_lists[i])
                        print (' ')

                                


                       
                                
def IPAddress(IP: str) -> str:
        if (ip_address(IP).is_private and ip_address(IP).is_link_local):
                return "APIPA" 

        elif (ip_address(IP).is_private and ip_address(IP).is_loopback):
                return "loopback" 

        elif(ip_address(IP).is_global):
                return "Public" 
        elif(IP == '0.0.0.0'):
                return "Default IP"

        elif(ip_address(IP).is_private):
                return "Private" 

if __name__ == '__main__' :

        ipCheck()
    

    
