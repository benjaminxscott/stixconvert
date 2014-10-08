#  Five Guys converter
Converts computer security indicators provided by international computer security partners

## Installation

```
sudo apt-get install python-dev python-pip libxml2-dev libxslt-dev zlib1g-dev

(under active virtualenv) 
> pip install stix
```
## Usage

```
./convert.py -h
usage: convert.py [-h] [--infile INFILE]
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
