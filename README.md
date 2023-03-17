## Overview
The CrowdSec Splunk app leverages the CrowdSec's CTI API's smoke endpoint which enables users to query an IP and receive enrichment

## Example Usage

The following command is used to run an IP check through the CrowdSec's CTI API's smoke endpoint. On the Homepage of Splunk Web Interface, select `Search & Reporting` and use the following command.

```
| makeresults | eval ip="<dest_ip>" | cssmoke ipfield="ip"
```

- cssmoke: 
    - Custom command driving the core functionality of the application.

- ipfield: 
    - It denotes the field name where the IP address is stored in the index.

## Results
On the event of clicking the `Search` button, users will be able to veiw a brief overview of various fields associated with the input IP address. This includes but not limited to location, behaviors, classifications, attack details – name, label, description, references followed by scores, threats, etc.
