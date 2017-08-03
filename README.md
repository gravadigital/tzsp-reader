# TZSP READER for Mikrotik.

Tzsp reader is a package reader coming from a mikrotik.
With this application you can easily see the consumption of the network in real time and monitor the traffic.


### Use

```
python tzsp-reader.py

```

### Prerequisites

before start you have to [configure sniffer](https://wiki.mikrotik.com/wiki/Manual:Tools/Packet_Sniffer) in the mikrotik.
### Screenshot
![screenshot](https://raw.githubusercontent.com/gravadigital/tzsp-reader/master/example/statustics.jpg)

### History ( -h option)
![screenshot](https://raw.githubusercontent.com/gravadigital/tzsp-reader/master/example/tzsp-reader.png)

## ChangeLog
### beta realease 0.0.4
* Corrections in consumption measurement
### beta realease 0.0.3
* ipfile.json added to display labels for ips
* fix local ip filter

### beta release 0.0.2
* In this version you can monitor the traffic and view logs in real time of the requests

### Planned improvements for realease:
* Better traffic monitoring
* Handle resize
* List of main countries
* Colors alarms
* Statistics
* Database connection for long-term analysis
