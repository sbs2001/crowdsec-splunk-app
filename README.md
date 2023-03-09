## Overview
The CrowdSec Splunk app leverages the CrowdSec's CTI API's smoke endpoint which enables users to query an IP. It runs an IP check against the CrowdSec CTI and returns the relevant fields including location, reverse_dns, behaviors, history, classifications, attack details, target countries, scores, and references by specifying the name of the IP address field with the required ipfield parameter. 

**Author**: CrowdSec \
**Version**: v0.0.1-rc2 \
**Prerequisites**: CrowdSec's CTI API Key

## Example Usage

The following command is used to run an IP check through the CrowdSec's CTI API's smoke endpoint. On the Homepage of Splunk Web Interface, select `Search & Reporting` and use the following command.

```
| makeresults | eval ip="<dest_ip>" | cssmoke ipfield="ip"
```

- cssmoke: 
    - Custom command driving the core functionality of the application.

- ipfield: 
    - This field identifies the IP address to run a check on and get briefed results regarding the same.

## Results
On the event of clicking the `Search` button, users will be able to veiw a brief overview of various fields associated with the input IP address. This includes but not limited to location, behaviors, classifications, attack details – name, label, description, references followed by scores, threats, etc.