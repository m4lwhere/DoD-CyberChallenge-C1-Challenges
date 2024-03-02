# C1-Challenges
Challenges for the C1 CTF

## Challenge Table

|Status|Title|Category|Difficulty|Tested Areas|Notes|
|------|-----|--------|----------|------------|-----|
|✅|Exfil|Forensics|Medium|PCAP Analysis |DNS exfil|
|❌|unk|Malware/RE|Medium|Malware Reversal|Cobalt Strike Powershell|
|✅|Ports|Networking & Recon|Easy|Scanning|Open Ports|
|❌|unk|Networking & Recon|Hard|Fuzzing|Fuzzing Scenarios?|
|❌|unk|Web|Medium|Find vulns in source|Reveal source code|

# Challenge Descriptions
Below is a description of each challenge, its purpose, and how to solve them.

## Exfil
### Description
We've been alerted that something's been stolen from our network, but none of our sensors found anything out of the ordinary. Can you find if a flag was stolen from our network in the packet capture attached?

### Tested Areas
This involves identifying interesting data which should be investigated further. Once this data is located, students are expected to isolate this further and then programmatically gather the subdomains. 

### Solution
This challenge involves identifying suspicious activity within a pcap file and isolating the interesting parts for analysis. There's over 700 packets to carve from the interesting data, which shouldn't be done by hand. Students will be expected to use a tool such as `tshark` or `scapy` to parse this information for us.

The shell command below is used to complete this in a single one-liner. This takes the pcap file, isolates the queries to the DNS server for the suspicious domain, then gathers only the DNS query. From this information, it will take just the interesting portion of the subdomain which is base32 encoded. 

```sh
tshark -r dns_exfil.pcapng -Y 'dns.qry.name contains "data.exfiltrated.com" && ip.dst == 8.8.8.8' -T fields -e dns.qry.name | awk -F. '{print $1}' | tr -d '\n'  | base32 -d > carved.jpg
```