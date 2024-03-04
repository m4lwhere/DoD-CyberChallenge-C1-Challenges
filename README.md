# C1-Challenges
Challenges for the C1 CTF

## Challenge Table

|Status|Title|Category|Difficulty|Tested Areas|Notes|
|------|-----|--------|----------|------------|-----|
|✅|Exfil|Forensics|Medium|PCAP Analysis |DNS exfil|
|❌|unk|Malware/RE|Medium|Malware Reversal|Cobalt Strike Powershell|
|✅|Ports|Networking & Recon|Easy|Scanning|Open Ports|
|❌|unk|Networking & Recon|Hard|Fuzzing|Fuzzing Scenarios?|
|✅|unk|Web|Medium|Find vulns in source|Reveal source code|

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

## Ephemeral
### Description 
We've received intelligence that an attacker is hosting flags for others to find. However, it seems that this flag is hosted on a non-standard port. Can you find the service and read the flag?

### Tested Areas
This revolves around a candidate's ability to scan all TCP ports to find an open port. The service is hosted on TCP port 51147.

### Solution
After the Docker container starts within CTFd, the candidate will be presented with an IP. The candidate will need to use a port scanning tool, such as `nmap` to scan all ports for a listening service.

```sh
nmap -p- -sV -v -T5 {{IP of Docker Container}}
```

### Artifacts
The following artifacts are provided to solve this challenge:

{{IP of Docker Container}}

## Secret Keepers Club
### Description
We've found a website which we believe is vulnerable to leaking secrets. Can you gather the secrets within the `admin` account?

### Tested Areas
This challenge tests a candidate's ability to find an exposed secret and then use that information to sign a forged JWT. 

### Solution
This challenge revolves around a candidate's ability to identify a leaked secret within a `.env` file, then crafting a new JWT which can be signed with the secret. This new JWT allows the candidate to read the admin's secret within the database.
1. Register an account, gather a legitimate JWT.
2. Locate the exposed .env file at `/.env`.
3. Load the legitimate JWT into a JWT debugger, such as [jwt.io](https://jwt.io).
4. Change the `username` to `admin` in the debugger. 
5. Add the leaked secret to the signing key in the debugger.