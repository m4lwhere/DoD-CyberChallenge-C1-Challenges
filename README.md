# C1-Challenges
Challenges for the C1 CTF

## Challenge Table

|Status|Title|Category|Difficulty|Tested Areas|Notes|
|------|-----|--------|----------|------------|-----|
|✅|Exfil|Forensics|Medium|PCAP Analysis |DNS exfil|
|✅|Ferromagnetic|Malware/RE|Medium|Malware Reversal|Cobalt Strike Powershell|
|✅|Ports|Networking & Recon|Easy|Scanning|Open Ports|
|❌|unk|Networking & Recon|Hard|Fuzzing|Fuzzing Scenarios?|
|✅|unk|Web|Medium|Web Exploitation Attacks|Find exposed secrets|

# Challenge Descriptions
Below is a description of each challenge, its purpose, and how to solve them.

## Exfil
### Description
We've been alerted that something's been stolen from our network, but none of our sensors found anything out of the ordinary. Can you find if a flag was stolen from our network in the packet capture attached?

### Hints
1. One set of queries is different than the others, isolate them!
2. The data is Base32 encoded. Keep it in order!
3. Don't do it manually! Use `tshark` or `scapy` to programmatically access the data.

### Tested Areas
This involves identifying interesting data which should be investigated further. Once this data is located, students are expected to isolate this further and then programmatically gather the subdomains. 

### Solution
This challenge involves identifying suspicious activity within a pcap file and isolating the interesting parts for analysis. There's over 700 packets to carve from the interesting data, which shouldn't be done by hand. Students will be expected to use a tool such as `tshark` or `scapy` to parse this information for us.

The shell command below is used to complete this in a single one-liner. This takes the pcap file, isolates the queries to the DNS server for the suspicious domain, then gathers only the DNS query. From this information, it will take just the interesting portion of the subdomain which is base32 encoded. 

```sh
tshark -r exfiltrated.pcap -Y 'dns.qry.name contains "data.exfiltrated.com" && ip.dst == 8.8.8.8' -T fields -e dns.qry.name | awk -F. '{print $1}' | tr -d '\n'  | base32 -d > carved.jpg
```

The flag is `C1{dns_3xfil7r4t3d!}`

## Ferromagnetic
### Description
We've intercepted a malicious file which appears to be doing something bad, can you find out what it is? The password to decrypt the ZIP is `infected`. 

Note: While the malicious actions themselves were removed, this file will set off Anti-Virus detections. 

### Hints
1. Review https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/
2. If you're using CyberChef, ensure the XOR is set to Decimal, not Hex!

### Tested Areas
This challenge tests the candidate's ability to reverse a PowerShell Cobalt Strike beacon. These types of files are used to launch the beacon on an asset to be used in follow-on attacks. Being able to decode these types of attacks helps an analyst identify and classify an attack against their organization. 

### Solution
Begin by extracting the file using the password `infected`. Once extracted and investigated, the candidate should notice that this file takes a Base64 string and decodes it.

Further analysis should give the candidate clues that this is a Cobalt Strike beacon. Googling for information should reveal more resources, such as the blog by Tony Lambert (https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/). 

The most important part is identifying the `$var_code` variable. This is XOR'd with the value `35` in order to hide the true intentions of the malware. 

Using a tool such as CyberChef, candidates can decode the Base64 and XOR the bytes to see the values. 
- NOTE: In CyberChef, ensure the XOR with `35` is set as `Decimal`, not `Hex`
- See sample below: 
    - https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Decimal','string':'35'%7D,'Standard',false)&input=V0UrY2I5UnVDUWpqVUN0UWlJMFRHQjRKMWRCUGdvMFYzTkNhOHV5UGpxbUJLOGREUk1DMWVYckN6VnRWcGVKd2hsMjBJZWFMUzNQNk42QzZEdjhCT3NyZ1NJSjRFOHJxSWlNank2amMzTndNVVZOQUl4d2tEMnZhVVlpUVVVbGlNejlqdXpUellBNkYwbzE4K0J5VzJNMU5sdzA3Y0JxUmEyZ3F5Mm5DWEZacGVJWGU3QnowK09uZ0NPNHQwbXdCVHFyRTU3cnloTHY3WjJrOGhaRzBJMnRNVUZjWkEyQVNXRTVDVDFSQ1VVWjhURUZGVmxCQVFsY1NFMDE4RjAxSGZFNFhUUkpUVms4WFYwb1RUUUplTGlsaVFFQkdVMWNaQXdrTUNTNHBkbEJHVVE1aVJFWk5WeGtEYmt4WlNrOVBRZ3dXRFJNREMzUktUVWRNVkZBRGJYY0RGUTBTQ2dOaVUxTlBSblJHUVdoS1Z3d1dFQlFORUJVREMyaHJkMjV2RHdOUFNraEdBMlJHUUVoTUNpNHBJMDB3clJHL3h1NURFN3RiZnZ0aGhxdTBnNmV0V05qQ3VQeUNKMEpqUW5pbHFpcGJCeHBxcHlxYzZITUJuUS9HZGJEMGxsNmRiZ2wzM1FlU3JIc1JMbGp4ZGNsSWxvNmYxZ3RXbzRLRXJTMVVUQTRkSVk2UkI5UFliMkFtNm51VDZVOVF0cUZmSCtCS2N1cHQ1T1pISk5FcWFQNjZRY3Y3VDRCV011Q200MWJHZStETGl0N2MzQklSRkEwVERSTU5FaU55S3B4Tw

Within the decrypted values, the flag exists: `C1{malware_obfuscat10n_4nd_m4n1pul4ti0n!}`


## Ephemeral
### Description 
We've received intelligence that an attacker is hosting flags for others to find. However, it seems that this flag is hosted on a non-standard port. Can you find the service and read the flag?

### Hints
1. Use `nmap` to search for open ports.
2. Make sure to check for ALL ports!

### Tested Areas
This revolves around a candidate's ability to scan all TCP ports to find an open port. The service is hosted on TCP port 51147.

### Solution
After the Docker container starts within CTFd, the candidate will be presented with an IP. The candidate will need to use a port scanning tool, such as `nmap` to scan all ports for a listening service.

```sh
nmap -p- -sV -v -T5 {{IP of Docker Container}}
```

### Artifacts
The following artifacts are provided to solve this challenge:

```
{{IP of Docker Container}}
```

The flag is `C1{ch3ck_4ll_p0rts!}`

## Secret Keepers Club
### Description
We've found a website which we believe is vulnerable to leaking secrets. Can you gather the secrets within the `admin` account?

### Hints
1. Debug JWTs with https://jwt.io
2. Is something stored in the ENVIRONMENT which is leaked?
3. Change the JWT and re-sign it!

### Tested Areas
This challenge tests a candidate's ability to find an exposed secret and then use that information to sign a forged JWT. 

### Solution
This challenge revolves around a candidate's ability to identify a leaked secret within a `.env` file, then crafting a new JWT which can be signed with the secret. This new JWT allows the candidate to read the admin's secret within the database.
1. Register an account, gather a legitimate JWT.
2. Locate the exposed .env file at `/.env`.
3. Load the legitimate JWT into a JWT debugger, such as [jwt.io](https://jwt.io).
4. Change the `username` to `admin` in the debugger. 
5. Add the leaked secret to the signing key in the debugger.

The flag is `C1{oops_I_l34k3d_my_k3ys!}`