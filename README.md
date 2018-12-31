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

```
filename:myvtfile.exe
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

Malicious submissions from Qatar are rare and often interesting if you're after threats in the Middle Eastern region. 
```
submitter:QA positives:2+
```
