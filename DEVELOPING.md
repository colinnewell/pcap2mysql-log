# Developing

## Creating tests

The --raw-data option allows you to gather the packet data from the original captures to allow you to craft tests.

So for example I might grep for a type of packet I'm interested in using gron:

```
./pcap2mysql-log test/captures/insecure.pcap --raw-data | gron | grep -C5 OK
json[0].Items[2].Data.Transmission = {};
json[0].Items[2].Data.Transmission.AffectedRows = 0;
json[0].Items[2].Data.Transmission.Info = "";
json[0].Items[2].Data.Transmission.LastInsertID = 0;
json[0].Items[2].Data.Transmission.ServerStatus = 0;
json[0].Items[2].Data.Transmission.Type = "OK";
json[0].Items[2].Data.Transmission.WarningCount = 0;
json[0].Items[2].Seen = [];
json[0].Items[2].Seen[0] = "2020-06-05T19:17:53.299068+01:00";
json[0].Items[3] = {};
json[0].Items[3].Data = {};
--
json[0].Items[12].Data.Transmission = {};
json[0].Items[12].Data.Transmission.AffectedRows = 1;
json[0].Items[12].Data.Transmission.Info = "";
json[0].Items[12].Data.Transmission.LastInsertID = 0;
json[0].Items[12].Data.Transmission.ServerStatus = 0;
json[0].Items[12].Data.Transmission.Type = "OK";
json[0].Items[12].Data.Transmission.WarningCount = 0;
json[0].Items[12].Seen = [];
json[0].Items[12].Seen[0] = "2020-06-05T19:18:45.184956+01:00";
json[1] = {};
json[1].Address = "192.168.32.3:48528 - 192.168.32.2:3306";
...
json[1].Items[12].Data.Transmission = {};
json[1].Items[12].Data.Transmission.AffectedRows = 1;
json[1].Items[12].Data.Transmission.Info = "";
json[1].Items[12].Data.Transmission.LastInsertID = 2;
json[1].Items[12].Data.Transmission.ServerStatus = 0;
json[1].Items[12].Data.Transmission.Type = "OK";
json[1].Items[12].Data.Transmission.WarningCount = 0;
json[1].Items[12].Seen = [];
json[1].Items[12].Seen[0] = "2020-06-05T19:18:37.319324+01:00";
json[2] = {};
json[2].Address = "192.168.32.3:48532 - 192.168.32.2:3306";
...
```

Then having found one that has the sort of structure I want focus on that using jq:

```
./pcap2mysql-log test/captures/insecure.pcap --raw-data | jq '.[1].Items[12].Data'
{
  "RawData": "BwAAAQABAgIAAAA=",
  "Transmission": {
    "AffectedRows": 1,
    "LastInsertID": 2,
    "ServerStatus": 0,
    "WarningCount": 0,
    "Type": "OK",
    "Info": ""
  }
}
```

Then to grab the raw data:

```
./pcap2mysql-log test/captures/insecure.pcap --raw-data | jq '.[1].Items[12].Data.RawData' -r
```

To turn it into something useful for tests I tend to use the quick go program at:
https://gist.github.com/colinnewell/b822fb73bfdd146719b0bbbd5b9b64e2

```
pcap2mysql-log test/captures/insecure.pcap --raw-data | jq '.[1].Items[12].Data.RawData' -r | base64 -d |
 go run hex-dump.go
0x07, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02,  // ........
0x00, 0x00, 0x00,  // ...
```

This can then be inserted into a test easily like:

```
    input := []byte{
        0x07, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02,  // ........
        0x00, 0x00, 0x00,  // ...
    }
```

## Creating test captures for test purposes

There is a docker-compose environment that spins up MySQL and then talks to it
to allow the creation of packet captures of the traffic.

	make captures

Capture files are produced in the tcpdump/ folder (in gitignore).

This docker-compose environment pushes all the containers onto the same ip
address so that the tcpdump can capture the traffic on localhost where the
communication occurs.
