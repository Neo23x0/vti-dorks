# vti-dorks
Awesome VirusTotal Intelligence Search Queries

## Purpose

This repo lists useful Virustotal Intelligence aka Virustotal Enterprise search queries that are useful for threat hunting purposes. Please provide your favorite search queries as pull requests. 

## General 

### Generic

```
filename:payload positives:5-
```

```
filename:exploit positives:5-
```

```
filename:myvtfile.exe
```

### Mimikatz

```
filename:mimi* positives:5-
```

```
filename:*katz.exe positives:5-
```

```
engines:mimikatz positives:5-
```

## Location Based

```
submitter:QA positives:2+
```
