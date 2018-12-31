# f5grep
Script that uses `grep' to search F5 BigIP configuration files.

Download `f5grep.py' and edit BIGIP_HOSTS to list all the F5 BigIP
servers you want to search.

## Co-requirements

Uses the "pexpect" module.

## Usage

```
	usage: f5grep.py [-h] [-E] [-i] [-ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
	                 pattern

	Script to run grep against the BigIP config files.

	positional arguments:
	  pattern               Look for a pattern in BigIP configuration files

	optional arguments:
	  -h, --help            show this help message and exit
	  -E, --extended-regexp
	                        Interpret the pattern as an extended regular
	                        expression (ERE)
	  -i, --ignore-case     Ignore case distinctions in both the pattern and the
	                        input files
	  -ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
	                        Set the logging level
```

## Example

Example using Basic Regular Expressions (BRE).


```
$ f5grep.py -E '192.168.50.1\>'
F5 userid to use [bopeep]?
F5 password for bopeep?

Found matches on xb15.local:
        /config/bigip.conf:142:    address 192.168.50.1
        /config/bigip.conf:259:            address 192.168.50.1

Found matches on xb16.local:
        /config/bigip.conf:142:    address 192.168.50.1
        /config/bigip.conf:259:            address 192.168.50.1

Found matches on xb17.local:
        /config/bigip.conf:5607:    address 192.168.50.1
        /config/bigip.conf:5649:            address 192.168.50.1

Found matches on xb18.local:
        /config/bigip.conf:5625:    address 192.168.50.1
        /config/bigip.conf:5667:            address 192.168.50.1
```
