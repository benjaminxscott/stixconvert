# ConvertMe
A converter for indicator data

`NOTE: Since representative input data is not available, this script will need modifications to work in production`

## Installation

```
apt-get install python-lxml zlib1g-dev
sudo pip install cybox
git clone https://github.com/STIXProject/python-stix.git 
sudo mv python-stix/stix /usr/lib/python2.7/stix
```

## Usage

```
./convert.py -h
usage: convert.py [-h] [--infile INFILE]
 
Parse a given CSV and output STIX XML 
 
optional arguments:
  -h, --help            show this help message and exit
  --infile INFILE, -f INFILE
                        input CSV with bot data (default: bots
.csv)
```

## Input Format

	ID is uniq
	Indicator is the "thing to look for"
	indValue is the "hash or registry key"
	Notes are freeform text
	InfectionType is either pre-post, or 'unknown'
	IndicatorType is IP, domain, email, URI, HTTP content? , File, User-agent, HTTP regex, Registry, Mutex
	Malware = either "sample" or not
	Reference = source where it came from
	GroupID = related indicators have the same GID
