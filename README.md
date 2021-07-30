# vti-dorks
Awesome VirusTotal Enterprise Search Queries (formerly Virustotal Intelligence or VTI) 

## Purpose

This repo lists useful Virustotal Enterprise search queries that are useful for threat hunting purposes. Please provide your favorite search queries as pull requests. 

## Generic
Show uploads named "payload" that have less than 5 antivirus eignes detecting them.
```
name:payload positives:5-
```
Show uploads named "exploit" that have less than 5 antivirus eignes detecting them. False positives are PDFs, web pages or documents with exploit descriptions.
```
name:exploit positives:5-
```
Show uploads that contain the keyword "obfus" in the filename and exclude android samples. (android samples obstruct view) The keyword "obfus" is often found in obfuscated malware samples. 
```
name:obfus NOT tag:android
```
Show executable files that identify as Microsoft software but are packed with an unusual packer and have less than 10 positive antivirus matches
```
metadata:"Microsoft Corporation" AND tag:peexe AND ( packer:rar OR packer:upx OR packer:themida OR packer:asprox ) AND positives:10-
```
Unknown origin - no description yet 
```
name:myvtfile.exe
```
Malware hosted on a government URL
```
itw:".gov" positives:5+
```
Find PE files submitted to VT, within n-seconds of compilation, that trigger at least 5 detections
```
subspan:300- positives:5+
```
You can tune it a bit using:
`submitter:US` - US submitter
`submitter:web` - web submitter
`submissions:2-` - submitted less then 2 times

## Mimikatz

Show samples with filenames starting with "mimi" (rare) that have less than 5 antivirus engines with matches. 
```
name:mimi* positives:5-
```
Show samples with filenames ending with "katz.exe" (rare) that have less than 5 antivirus engines with matches. 
```
name:*katz.exe positives:5-
```
Show samples with some antivirus engines matches. These are often obfuscated Mimikatz variants.
```
engines:mimikatz positives:5-
```

## Special Threat Related

Example way to find Shamoon using the resource names:
```
resource:"PKCS7" and resource:"X509"
```
Reference: https://unit42.paloaltonetworks.com/unit42-shamoon-2-return-disttrack-wiper/

## Location Based
Show samples submitted from Germany with low antivirus coverage that could be successful phishing campaigns.  
```
submitter:DE positives:2+ positives:10- (tag:doc OR tag:docx)
```
Show samples submitted from Taiwan with low antivirus coverage that could be successful NEW phishing campaigns (only 1 submitter).  
```
submitter:TW positives:1+ positives:20- filename:*.eml submissions:1
```
Malicious submissions from Qatar are rare and often interesting if you're after threats in the Middle Eastern region. 
```
submitter:QA positives:2+
```
Show samples submitted from Israel with the keyword "Syria" in the filename that have 2 or more antivirus engines matching. 
```
submitter:IL name:syria positives:2+
```

## macOS
Hunting signed macOS DMGs with minimum detections (often caused by heuristics) 
```
ls:2019-01-16+ type:dmg positives:2+ tag:signed
```
## ELF
Hunting for ELF binaries belonging to the MIRAI family
```
tag:elf AND p:2+ AND engines:Mirai
```
Hunting for ELF binaries excluding MIRAI and DDOS malware
```
tag:elf AND p:5+ NOT engines:Mirai NOT engines:DDOS
```

## Sandbox result searches
VTi has several Sandboxes that will scan the behavior of the submitted files; searching for categories combined with tags can be useful.

Search for ransomware using the Lastline sandbox:
```
lastline:RANSOM 
```
Searching for stealers in the pe format on C2AE sandbox. (STEALER/MALWARE/TROJAN are some keywords used by this sandbox)
```
c2ae:STEALER and tag:peexe
```

## Content Searches (New Feature)

Content searches cannot be combined with other conditions. 

Search for well-known mimikatz keyword in any type of sample. 
```
content:"sekurlsa::logonpasswords"
```
Detects phishing documents that ask the user to activate macros
```
content:"click enable editing"
content:"click enable content"
```
Detects exploit codes 
```
content:"] Shellcode"
```

## Sample Similarities

Content searches for malware similarities.

VT Feature Hash is an internal hash used by Virustotal.
```
similar-to:<hashofthefile>
```

Code Blocks is used to look for samples that contain the same pieces of code.
```
code-similar-to:<hashofthefile>
```

ImpHash is a well-known hash calculated with the Import Address Table to identify samples using the same imported functions.
```
imphash:<IATHash>
```

PE Rich Hash is a hash calculated from Rich Header.
```
rich_pe_header_hash:<Richhash>
```

TLSH is used to generate hash values which can then be analyzed for similarities.
```
tlsh:<tlshash>
```

SSDEEP is a fuzzing algorithm that can be used for the same purpose. 
```
ssdeep:<ssdeep_hash>
```

The other functions are used to identify similarity based on behavior identified with sandbox analysis. 
```
behash:<hashofthefile>
```

Files with a visually similar icon or thumbnail.
```
main_icon_dhash:<icon_hash>
```

.NET files that were built in one project have the same GUID value
```
netguid:<GUID>
```

