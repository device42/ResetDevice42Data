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

    def get(self, url, id_name, name):
        url = D42_URL + url
        response = requests.get(url, headers=self.headers, verify=False)
        raw = response.json()

        ids = [x[id_name] for x in raw[name]]
        offset = limit = total = 0
        if raw.has_key('offset'):
            offset = raw['offset']
        if raw.has_key('limit'):
            limit = raw['limit']
        if raw.has_key('total_count'):
            total = raw['total_count']
        return ids, offset, limit, total

    def delete_devices(self):
        """
        Deleting device one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting devices'
        while 1:
            url = '/api/1.0/devices/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'device_id', 'Devices')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Device ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/devices/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_racks(self):
        """
        Deletes racks
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting racks'
        while 1:
            url = '/api/1.0/racks/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'rack_id', 'racks')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Rack ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/racks/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_buildings(self):
        """
        Deletes buildings and rooms as well
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting buildings'
        while 1:
            url = '/api/1.0/buildings/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'building_id', 'buildings')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Building ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/buildings/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_pdus(self):
        """
        Deletes PDUs, but it does not delete PDU models
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting PDUs'
        while 1:
            url = '/api/1.0/pdus/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'pdu_id', 'pdus')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] PDU ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/pdus/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_subnets(self):
        """
        Deletes subnets and IPs as well
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting subnets'
        while 1:
            url = '/api/1.0/subnets/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'subnet_id', 'subnets')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Subnet ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/subnets/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_assets(self):
        """
        Deleting assets one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting assets'
        while 1:
            url = '/api/1.0/assets/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'asset_id', 'assets')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Asset ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/assets/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_hardwares(self):
        """
        Deleting hardwares one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting hardwares'
        while 1:
            url = '/api/1.0/hardwares/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'hardware_id', 'models')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Hardware ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/hardwares/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_macs(self):
        """
        Deleting macs one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting MACs'
        while 1:
            url = '/api/1.0/macs/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'macaddress_id', 'macaddresses')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] MAC ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/macs/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_vlans(self):
        """
        Deleting VLANs one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting VLANs'
        while 1:
            url = '/api/1.0/vlans/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'vlan_id', 'vlans')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] VLAN ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/vlans/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i+=1

    def delete_parts(self):
        """
        Deleting parts one at the time. Very slow!
        :return:
        """
        all_ids = []
        offset = 0
        print '\n[!] Deleting parts'
        while 1:
            url = '/api/1.0/parts/?offset=%s' % offset
            ids, offset, limit, total_count = self.get(url, 'part_id', 'parts')
            all_ids.extend(ids)
            offset  += limit
            if offset >= total_count:
                break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print '\t[-] Part ID: %s [%d of %d]' % (obj_id, i, total)
            f = '/api/1.0/parts/%s/' % obj_id
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
    
def cancel():
    print '\nCancelled'
    sys.exit()

def main():
    w = Wipe()
    parser = argparse.ArgumentParser(prog="deleter")
    parser.add_argument('-r', '--racks', action="store_true", help='Delete all Racks')
    parser.add_argument('-b', '--buildings', action="store_true", help='Delete all Buildings')
    parser.add_argument('-p', '--pdus', action="store_true", help='Delete all PDUs')
    parser.add_argument('-s', '--subnets', action="store_true", help='Delete all Subnets')
    parser.add_argument('-d', '--devices', action="store_true", help='Delete all Devices')
    parser.add_argument('-i', '--assets', action="store_true", help='Delete all Assets')
    parser.add_argument('-w', '--hardwares', action="store_true", help='Delete all Hardwares')
    parser.add_argument('-m', '--macs', action="store_true", help='Delete all MACs')
    parser.add_argument('-v', '--vlans', action="store_true", help='Delete all VLANs')
    parser.add_argument('-t', '--parts', action="store_true", help='Delete all parts')
    parser.add_argument('-a', '--all', action="store_true", help='Delete EVERYTHING')
    args = parser.parse_args()

    if len(sys.argv) == 1:
        print parser.print_help()
    else:
        if args.racks:
            if print_warning("racks"):
                print '\n Deleting Racks ...'
                w.delete_racks()
            else:
                cancel()
        if args.buildings:
            if print_warning("buildings"):
                print '\n Deleting Buildings'
                w.delete_buildings()
            else:
                cancel()
        if args.pdus:
            if print_warning("pdus"):
                print '\n Deleting PDUs'
                w.delete_pdus()
            else:
                cancel()
        if args.subnets:
            if print_warning("subnets"):
                print '\n Deleting Subnets'
                w.delete_subnets()
            else:
                cancel()
        if args.devices:
            if print_warning("devices"):
                print '\n Deleting Devices'
                w.delete_devices()
            else:
                cancel()
        if args.assets:
            if print_warning("assets"):
                print '\n Deleting Assets'
                w.delete_assets()
            else:
                cancel()
        if args.hardwares:
            if print_warning("hardwares"):
                print '\n Deleting hardwares'
                w.delete_hardwares()
            else:
                cancel()
        if args.macs:
            if print_warning("MACs"):
                print '\n Deleting MACs'
                w.delete_macs()
            else:
                cancel()
        if args.vlans:
            if print_warning("VLANs"):
                print '\n Deleting VLANs'
                w.delete_vlans()
            else:
                cancel()
        if args.parts:
            if print_warning("parts"):
                print '\n Deleting parts'
                w.delete_parts()
            else:
                cancel()
        if args.all:
            if print_warning("EVERYTHING"):
                print '\n DELETING EVERYTHING ...'
                w.delete_racks()
                w.delete_buildings()
                w.delete_pdus()
                w.delete_subnets()
                w.delete_devices()
                w.delete_assets()
                w.delete_hardwares()
                w.delete_macs()
                w.delete_vlans()
                w.delete_parts()
            else:
                cancel()


if __name__ == '__main__':
    main()
    print '\n[!] Done!\n\n'
    sys.exit()
