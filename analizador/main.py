from ReputationIp import ipCheck
from hash import *
from cve import cveCheck
from keys import keyReturn
import requests
from requests.auth import HTTPBasicAuth
from ipaddress import ip_address
import json

def main():

        try:    
                
                print ("Created by Geovanni Munoz Otarola")
                print ('---------------------------------------------------------------')
                print(' Please choose the option: ')
                print(' Check the reputation Ip        -------> 1 ')
                print(' Check the reputation Hash      -------> 2 ')
                print(' Check the CVE                  -------> 3 ')
                print(' For Exit please enter 0        -------> 0 ')
                print(' ')
                data=keyReturn()
        
                opt = int(input('option : '))

                while (opt!=0):

                        if(opt==1):
                                ipCheck(data)
                        elif (opt==2):
                                hashCall(data)
                        elif (opt==3):
                                cveCheck(data)
                        print ("Created by Geovanni Munoz Otarola")
                        print ('---------------------------------------------------------------')
                        print(' Please choose the option: ')
                        print(' Check the reputation Ip        -------> 1 ')
                        print(' Check the reputation Hash      -------> 2 ')
                        print(' Check the CVE                  -------> 3 ')

                        print(' For Exit please enter 0        -------> 0 ')
                        print(' ')

                        opt = int(input('option : '))

        except:
                main()


if __name__ == '__main__' :
        
        main()
