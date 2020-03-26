import sys
import requests  
import base64
import argparse

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

D42_USER = 'username'
D42_PWD = 'p@ass'
D42_URL = 'https://fqdn'
DATA_STR = D42_USER + ':' + D42_PWD
DATA_BYTES = DATA_STR.encode("utf-8")
AUTH_STR = base64.b64encode(DATA_BYTES)

class Wipe():
    def __init__(self):
        self.headers = {
            'Authorization': 'Basic ' + AUTH_STR.decode(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def get(self, url, id_name, name):
        url = D42_URL + url
        response = requests.get(url, headers=self.headers, verify=False)
        raw = response.json()

        ids = [x[id_name] for x in raw[name]]
        offset = limit = total = 0
        if 'offset' in raw:
            offset = raw['offset']
        if 'limit' in raw:
            limit = raw['limit']
        if 'total_count' in raw:
            total = raw['total_count']
        return ids, offset, limit, total

    def delete_devices(self, ids_to_remove):
        """
        Deleting device one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting devices')
            while 1:
                url = '/api/1.0/devices/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'device_id', 'Devices')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Device ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/devices/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_racks(self, ids_to_remove):
        """
        Deletes racks
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting racks')
            while 1:
                url = '/api/1.0/racks/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'rack_id', 'racks')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Rack ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/racks/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_buildings(self, ids_to_remove):
        """
        Deletes buildings and rooms as well
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting buildings')
            while 1:
                url = '/api/1.0/buildings/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'building_id', 'buildings')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Building ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/buildings/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_pdus(self, ids_to_remove):
        """
        Deletes PDUs, but it does not delete PDU models
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting PDUs')
            while 1:
                url = '/api/1.0/pdus/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'pdu_id', 'pdus')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] PDU ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/pdus/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_subnets(self, ids_to_remove):
        """
        Deletes subnets and IPs as well
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting subnets')
            while 1:
                url = '/api/1.0/subnets/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'subnet_id', 'subnets')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Subnet ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/subnets/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_assets(self, ids_to_remove):
        """
        Deleting assets one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting assets')
            while 1:
                url = '/api/1.0/assets/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'asset_id', 'assets')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Asset ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/assets/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_hardwares(self, ids_to_remove):
        """
        Deleting hardwares one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting hardwares')
            while 1:
                url = '/api/1.0/hardwares/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'hardware_id', 'models')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Hardware ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/hardwares/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_ips(self, ids_to_remove):
        """
        Deletes ips
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting ips')
            while 1:
                url = '/api/1.0/ips/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'id', 'ips')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Ip ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/ips/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_macs(self, ids_to_remove):
        """
        Deleting macs one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting MACs')
            while 1:
                url = '/api/1.0/macs/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'macaddress_id', 'macaddresses')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] MAC ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/macs/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_vlans(self, ids_to_remove):
        """
        Deleting VLANs one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting VLANs')
            while 1:
                url = '/api/1.0/vlans/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'vlan_id', 'vlans')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] VLAN ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/vlans/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1

    def delete_parts(self, ids_to_remove):
        """
        Deleting parts one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting parts')
            while 1:
                url = '/api/1.0/parts/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'part_id', 'parts')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Part ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/1.0/parts/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1
			
    def delete_serviceinstances(self, ids_to_remove):
        """
		Added - 03/24/2020 - Not part of Wipe all
        Deleting service instances (si) one at the time. Very slow!
        :return:
        """
        if len(ids_to_remove) > 0:
            all_ids = ids_to_remove
        else:
            all_ids = []
            offset = 0
            print ('\n[!] Deleting service instances')
            while 1:
                url = '/api/2.0/service_instances/?offset=%s' % offset
                ids, offset, limit, total_count = self.get(url, 'serviceinstance_id', 'Service Instances')
                all_ids.extend(ids)
                offset += limit
                if offset >= total_count:
                    break

        total = len(all_ids)
        i = 1
        for obj_id in all_ids:
            print ('\t[-] Service Instance ID: %s [%d of %d]' % (obj_id, i, total))
            f = '/api/2.0/service_instances/%s/' % obj_id
            url = D42_URL + f
            r = requests.delete(url, headers=self.headers, verify=False)
            i += 1			


def print_warning(section, file=None):
    if file:
        print ('\n')
        print ('!!! WARNING !!!\n')
        print ("This WILL Delete all %s ids that presents in file %s\n" % (section, file))
        print ('!!! WARNING !!!\n')
    else:
        print ('\n')
        print ('!!! WARNING !!!\n')
        print ("This WILL Delete all of your %s\n" % (section))
        print ('!!! WARNING !!!\n')
    response = input("Please Type 'YES' to confirm deletion: ")
    if response == 'YES':
        return True
    else:
        return False


def cancel():
    print ('\nCancelled')
    sys.exit()


def main():
    w = Wipe()
    parser = argparse.ArgumentParser(prog="deleter")
    parser.add_argument('-r', '--racks', action="store_true", help='Delete Racks')
    parser.add_argument('-b', '--buildings', action="store_true", help='Delete Buildings')
    parser.add_argument('-p', '--pdus', action="store_true", help='Delete PDUs')
    parser.add_argument('-s', '--subnets', action="store_true", help='Delete Subnets')
    parser.add_argument('-d', '--devices', action="store_true", help='Delete Devices')
    parser.add_argument('-i', '--assets', action="store_true", help='Delete Assets')
    parser.add_argument('-w', '--hardwares', action="store_true", help='Delete Hardwares')
    parser.add_argument('-n', '--ips', action="store_true", help='Delete IPs')
    parser.add_argument('-m', '--macs', action="store_true", help='Delete MACs')
    parser.add_argument('-v', '--vlans', action="store_true", help='Delete VLANs')
    parser.add_argument('-t', '--parts', action="store_true", help='Delete parts')
    parser.add_argument('-a', '--all', action="store_true", help='Delete EVERYTHING')
    parser.add_argument('-f', '--file', nargs='?', help='Get IDS from supplied file')
    parser.add_argument('-e', '--serviceinstance', action="store_true", help='Delete Service Instances')	
    args = parser.parse_args()

    ids_to_remove = []
    if args.file and args.all:
        print ('Argument --file not allowed to use with --all')
        sys.exit()

    if args.file:
        ids_to_remove = []
        try:
            for line in open(args.file, 'r').readlines():
                ids_to_remove.append(line.replace('\n', ''))
        except TypeError:
            print ('Error with file open')
            sys.exit()

    if len(sys.argv) == 1:
        print (parser.print_help())
    else:
        if args.racks:
            if print_warning("racks", args.file):
                print ('\n Deleting Racks ...')
                w.delete_racks(ids_to_remove)
            else:
                cancel()
        if args.buildings:
            if print_warning("buildings", args.file):
                print ('\n Deleting Buildings')
                w.delete_buildings(ids_to_remove)
            else:
                cancel()
        if args.pdus:
            if print_warning("pdus", args.file):
                print ('\n Deleting PDUs')
                w.delete_pdus(ids_to_remove)
            else:
                cancel()
        if args.subnets:
            if print_warning("subnets", args.file):
                print ('\n Deleting Subnets')
                w.delete_subnets(ids_to_remove)
            else:
                cancel()
        if args.devices:
            if print_warning("devices", args.file):
                print ('\n Deleting Devices')
                w.delete_devices(ids_to_remove)
            else:
                cancel()
        if args.assets:
            if print_warning("assets", args.file):
                print ('\n Deleting Assets')
                w.delete_assets(ids_to_remove)
            else:
                cancel()
        if args.hardwares:
            if print_warning("hardwares", args.file):
                print ('\n Deleting hardwares')
                w.delete_hardwares(ids_to_remove)
            else:
                cancel()
        if args.ips:
            if print_warning("ips", args.file):
                print ('\n Deleting ips')
                w.delete_ips(ids_to_remove)
            else:
                cancel()
        if args.macs:
            if print_warning("MACs", args.file):
                print ('\n Deleting MACs')
                w.delete_macs(ids_to_remove)
            else:
                cancel()
        if args.vlans:
            if print_warning("VLANs", args.file):
                print ('\n Deleting VLANs')
                w.delete_vlans(ids_to_remove)
            else:
                cancel()
        if args.parts:
            if print_warning("parts", args.file):
                print ('\n Deleting parts')
                w.delete_parts(ids_to_remove)
            else:
                cancel()
        if args.serviceinstance:
            if print_warning("serviceinstances", args.file):
                print ('\n Deleting serviceinstances')
                w.delete_serviceinstances(ids_to_remove)
            else:
                cancel()				
        if args.all:
            if print_warning("EVERYTHING"):
                print ('\n DELETING EVERYTHING ...')
                w.delete_racks(ids_to_remove)
                w.delete_buildings(ids_to_remove)
                w.delete_pdus(ids_to_remove)
                w.delete_subnets(ids_to_remove)
                w.delete_devices(ids_to_remove)
                w.delete_assets(ids_to_remove)
                w.delete_hardwares(ids_to_remove)
                w.delete_macs(ids_to_remove)
                w.delete_vlans(ids_to_remove)
                w.delete_parts(ids_to_remove)
            else:
                cancel()


if __name__ == '__main__':
    main()
    print ('\n[!] Done!\n\n')
    sys.exit()
