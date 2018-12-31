# vti-dorks
Awesome VirusTotal Intelligence Search Queries

## Purpose

This repo lists useful Virustotal Intelligence aka Virustotal Enterprise search queries that are useful for threat hunting purposes. Please provide your favorite search queries as pull requests. 

## Generic
Show uploads named "payload" that have less than 5 antivirus eignes detecting them.
```
filename:payload positives:5-
```
Show uploads named "exploit" that have less than 5 antivirus eignes detecting them. False positives are PDFs, web pages or documents with exploit descriptions.
```
filename:exploit positives:5-
```
Show uploads that contain the keyword "obfus" in the filename and exclude android samples. (android samples obstruct view) The keyword "obfus" is often found in obfuscated malware samples. 
```
filename:obfus NOT tag:android
```
Unknown origin - no description yet 
```
filename:myvtfile.exe
```
Malware hosted on a government URL
```
itw:".gov" positives:5+
```

## Mimikatz
Show samples with filenames starting with "mimi" (rare) that have less than 5 antivirus engines with matches. 
```
filename:mimi* positives:5-
```
Show samples with filenames ending with "katz.exe" (rare) that have less than 5 antivirus engines with matches. 
```
filename:*katz.exe positives:5-
```
Show samples with some antivirus engines matches. These are often obfuscated Mimikatz variants.
```
engines:mimikatz positives:5-
```

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
submitter:IL filename:syria positives:2+
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

