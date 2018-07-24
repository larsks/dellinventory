# Tools for querying the Redfish API on Dell iDRACs

This repository contains the `dellinventory.py` script, which uses the
[Redfish][] API provided by recent Dell iDRAC firmware to query a set
of iDRACs for hardware inventory information.

## dellinventory.py

This script will query multiple iDRACs in parallel to acquire
inventory information and write it out in JSON format.

To read a list of iDRAC addresses from the file `hosts` and write out
JSON content in `inventory.json`:

    ./dellinventory.py -u root:calvin -l3 -o inventory.json -f hosts

(The `-l3` limits the tool to creating 3 simultaneous connections per
iDRAC. When using the default behavior, which allows for an arbitrary
number of simultaneous connections, there are occasional dropped
connections.)

To get information from a single host:

    ./dellinventory.py -u root:calvin -l3 -o 10.0.3.1.json 10.0.3.1

If you have an existing inventory in `inventory.json` and you want to add or
update it with information from one or more hosts, you can use the
`[jq][]` command to merge together multiple JSON documents:

    jq -s '.[0] + .[1]' inventory.json 10.0.3.1.json  > merged_inventory.json

[jq]: https://stedolan.github.io/jq/
[redfish]: https://www.dmtf.org/standards/redfish

## write-inventory.yml

An Ansible playbook that reads the JSON content generated by
`dellinventory.py` and uses it to produce a simple CSV report.

    ansible-playbook write-inventory.yml

This assumes that the file `inventory.json` exists in the current
directory.