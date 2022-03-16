import sys
import os
import requests
import argparse
import yaml
import csv
import ssl
import logging
ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fortigate', default='172.17.101.57', help='Firewall IP Address')
    parser.add_argument('--token', default='', help='API Token')
    parser.add_argument('--logging', default='', help='Logging levels info, error, or debug')
    parser.add_argument('--devlist', default='address.csv', help='YAML/CSV file with list of approved devices.')
    args = parser.parse_args()

    # Only enable logging when necessary
    if args.logging != '':
        logginglevel = args.logging
        formattedlevel = logginglevel.upper()

        # Open logfile
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',filename='address.log', level=formattedlevel, datefmt='%Y-%m-%d %H:%M:%S')
    else:
        ()
    
    # Open variable file either csv or yaml
    filetype = args.devlist.split('.')
    
    if filetype[1] == 'yml':
        # Open YAML variable file
        with open(os.path.join(sys.path[0],args.devlist), 'r') as vars_:
            data = yaml.safe_load(vars_)
    
    elif filetype[1] == 'csv':
        devices = []
        with open(os.path.join(sys.path[0],args.devlist), 'r') as vars_:
            for line in csv.DictReader(vars_):
                devices.append(line)
        data = {'all': devices}

    try:
        token = args.token
        address_url = 'http://%s/api/v2/cmdb/firewall/address' % args.fortigate
        headers = {'Authorization': 'Bearer' + token, 
                    'content-type': 'application/json'}

        for addr in data['all']:
            if addr['type'] == 'ipmask':
                data = {
                    'name': addr['name'],
                    'type': addr['type'],
                    'subnet': addr['subnet'],
                    'allow-routing': addr['allow-routing']
                }
                addresses = requests.post(address_url, headers=headers, json=data, verify=False)
            elif addr['type'] == 'fqdn':
                data = {
                    'name': addr['name'],
                    'type': addr['type'],
                    'fqdn': addr['fqdn'],
                    'allow-routing': addr['allow-routing']
                }
                addresses = requests.post(address_url, headers=headers, json=data, verify=False)
            
            if addresses.status_code == 200:
                logging.info('Address %s added' % addr['name'])
            else:
                logging.error('Unable to add address %s' % addr['name'])
        
        # addresses = requests.post(url, headers=headers, json={
        #     'name': 'web2', 
        #     'type': 'ipmask', 
        #     'subnet': '13.13.13.1/24', 
        #     'allow-routing': 'false', 
        #     }, verify=False)
        # pprint.pprint(addresses.status_code)


    except:
        logging.error('Unable to connect to Firewall')


if __name__ == '__main__':
   main()