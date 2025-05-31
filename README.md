# FRRTT
### First Response Rapid Traige Tool

The tool performs three major analysis tasks:

  1. File hash generation and VirusTotal lookup – Extract file hashes and checks them
  against VirusTotal to identify malicious files.

  2. EVTX log analysis using Chainsaw – Extract EVTX (Windows Event Log) files and
  analyzes them using Chainsaw and Sigma rules to detect malicious activity.

  3. PCAP analysis using Suricata – Extract PCAP (network capture) files and runs them
  through Suricata to detect network-based threats.

In essense, the tool will perform preliminary steps of a digital forensic investigation and determine any visible signs of infection on the system by performing the steps listed above.

### Dependencies

You need the following tools to run this script. These have to be installed on your forensic workstation in order to begin the analysis.  

  1. Suricata
  2. Chainsaw
  3. Sleuthkit
  4. Python
Other than these softwares, you need a virustotal API key. 

### Instructions

  1. Replace all the "Input_Path" values with the actual paths required.
  2. Run the script using python on .dd files.
  3. Basic user interaction can be done on the terminal at runtime.






