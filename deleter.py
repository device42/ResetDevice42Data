import sys
import requests
import base64
import argparse

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

D42_USER    = 'admin'
D42_PWD     = 'adm!nd42'
D42_URL     = 'https://192.168.3.30'


class Wipe():
    def __init__(self):
        self.headers = {
            'Authorization': 'Basic ' + base64.b64encode(D42_USER + ':' + D42_PWD),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def delete_racks(self):
        """
        Deletes racks
        :return:
        """
        print '\n[!] Deleting racks'
        f = '/api/1.0/racks/'
        url = D42_URL+f
        response = requests.get(url,headers=self.headers, verify=False)
        raw = response.json()
        racks = [x['rack_id'] for x in raw['racks']]

        for rack in racks:
            print '\t[-] Rack ID: %s' % rack
            f = '/api/1.0/racks/%s/' % rack
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)

    def delete_buildings(self):
        """
        Deletes buildings and rooms as well
        :return:
        """
        print '\n[!] Deleting buildings'
        f = '/api/1.0/buildings/'
        url = D42_URL+f
        response = requests.get(url,headers=self.headers, verify=False)
        raw = response.json()

        buildings = [x['building_id'] for x in raw['buildings']]

        for building in buildings:
            print '\t[-] Building ID: %s' % building
            f = '/api/1.0/buildings/%s/' % building
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)

    def delete_pdus(self):
        """
        Deletes PDUs, but it does not delete PDU models
        :return:
        """
        print '\n[!] Deleting pdus'
        f = '/api/1.0/pdus/'
        url = D42_URL+f
        response = requests.get(url,headers=self.headers, verify=False)
        raw = response.json()

        pdus = [x['pdu_id'] for x in raw['pdus']]

        for pdu in pdus:
            print '\t[-] PDU ID: %s' % pdu
            f = '/api/1.0/pdus/%s/' % pdu
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)


    def delete_subnets(self):
        """
        Deletes subnets and IPs as well
        :return:
        """
        print '\n[!] Deleting subnets'
        f = '/api/1.0/subnets/'
        url = D42_URL+f
        response = requests.get(url,headers=self.headers, verify=False)
        raw = response.json()

        subnets = [x['subnet_id'] for x in raw['subnets']]

        for subnet in subnets:
            print '\t[-] Subnet ID: %s' % subnet
            f = '/api/1.0/subnets/%s/' % subnet
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)

    def delete_devices(self):
        """
        Deleting device one at the time. Very slow!
        :return:
        """
        print '\n[!] Deleting devices'
        f = '/api/1.0/devices/'
        url = D42_URL+f
        response = requests.get(url,headers=self.headers, verify=False)
        raw = response.json()

        devices = [x['device_id'] for x in raw['Devices']]
        total = len(devices)
        i = 1
        for device in devices:
            print '\t[-] Device ID: %s [%d of %d]' % (device, i, total)
            f = '/api/1.0/devices/%s/' % device
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

def print_warning(section):
    print '\n'
    print '!!! WARNING !!!\n'
    print "This WILL Delete all of your %s\n" % (section)
    print '!!! WARNING !!!\n'
    response = raw_input("Please Type 'YES' to confirm deletion: ")
    if response == 'YES':
      return True
    else:
      return False

def main():
    w = Wipe()
    parser = argparse.ArgumentParser(prog="deleter")
    parser.add_argument('-r', '--racks', action="store_true", help='Delete all Racks')
    parser.add_argument('-b', '--buildings', action="store_true", help='Delete all Buildings')
    parser.add_argument('-p', '--pdus', action="store_true", help='Delete all PDUs')
    parser.add_argument('-s', '--subnets', action="store_true", help='Delete all subnets')
    parser.add_argument('-d', '--devices', action="store_true", help='Delete all Devices')
    parser.add_argument('-a', '--all', action="store_true", help='Delete EVERYTHING')
    args = parser.parse_args()
    
    if args.racks:
      if print_warning("racks"):
        print '\n Deleting Racks ...'
        w.delete_racks()
      else:
        print 'Cancelled'
        sys.exit()
    if args.buildings:
      if print_warning("buildings"):
        print '\n Deleting Buildings'
        w.delete_buildings()
      else:
        print 'Cancelled'
        sys.exit()
    if args.pdus:
      if print_warning("pdus"):
        print '\n Deleting PDUs'
        w.delete_pdus()
      else:
        print 'Cancelled'
        sys.exit()
    if args.subnets:
      if print_warning("subnets"):
        print '\n Deleting Subnets'
        w.delete_subnets()
      else:
        print 'Cancelled'
        sys.exit()
    if args.devices:
      if print_warning("EVERYTHING"):
        print '\n DELETING EVERYTHING ...'
        w.delete_racks()
        w.delete_buildings()
        w.delete_pdus()
        w.delete_subnets()
        w.delete_devices()
      else:
        print 'Cancelled'
        sys.exit() 




if __name__ == '__main__':
    main()
    print '\n[!] Done!'
    sys.exit()