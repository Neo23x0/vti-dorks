# vti-dorks
Awesome VirusTotal Intelligence Search Queries

## Purpose

This repo lists useful Virustotal Intelligence aka Virustotal Enterprise search queries that are useful for threat hunting purposes. Please provide your favorite search queries as pull requests. 

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

## VirusTotal Features

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
Show samples submitted from Germany with low antivirus coverage that could be successful new phishing campaigns.  
```
submitter:DE positives:2+ positives:10- (tag:doc OR tag:docx)
```
Malicious submissions from Qatar are rare and often interesting if you're after threats in the Middle Eastern region. 
```
submitter:QA positives:2+
```
Show samples submitted from Israel with the keyword "Syria" in the filename that have 2 or more antivirus engines matching. 
```
submitter:IL name:syria positives:2+
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
