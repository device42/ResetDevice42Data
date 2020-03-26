# ResetDevice42Data
This clears existing data in Device42. Use for reset only. Limited to certain categories for now.

Run deleter.py. It fetchest the IDs for objects using the GET call and deletes the objects using the ID for each object. Or get ids from supplied file and delete the objects same way.

# Possible Options
'-r', '--racks', `Delete all Racks`

'-b', '--buildings', `Delete all Buildings`

'-p', '--pdus', `Delete all PDUs`

'-s', '--subnets', `Delete all Subnets`

'-d', '--devices', `Delete all Devices`

'-i', '--assets', `Delete all Assets`

'-w', '--hardwares', `Delete all Hardwares`

'-n', '--ips',`Delete all IPs`

'-m', '--macs',`Delete all MACs`

'-v', '--vlans', `Delete all VLANs`

'-t', '--parts', `Delete all parts`

'-a', '--all', `Delete EVERYTHING`

'-f', '--file' `Get IDS from supplied file`

'-e', '--serviceinstance, `Delete all Service Instances`

# Examples of use
`python deleter.py --racks` - delete all racks.

`python deleter.py --buildings` - delete all buildings.

`python deleter.py --racks --file ids.csv` - delete racks by ids from ids.csv file.

`python deleter.py --all` - delete all possible objects.
