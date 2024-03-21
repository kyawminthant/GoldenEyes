# Web App Security Scanning Tool
**Title**: Web Application Security Scanning Tool ( GoldenEyes) <br>
**Tutor**: [Antons Patļins](https://ortus.rtu.lv/science/en/experts/5551), **Tutor**: [María Dolores Cano Baños](https://personas.upct.es/en/profile/mdolores.cano) <br>
**Degree**: Master of Cybersecurity Engineering [Riga Technical University](https://www.rtu.lv/en) <br>
**Degree**: Telecommunication engineering, [Polytechnic University of Cartagena](https://www.upct.es/) 

# Introduction
GoldenEyes is an advanced web security tool that efficiently checks for vulnerabilities in your web applications. It combines various techniques, including popular tools like waybackurls and curl, to thoroughly scan your applications and highlight any potential issues. The scan results are displayed in a simple format in the terminal, focusing only on the vulnerabilities found for further investigation. Thanks to its lightweight design and fast operation, GoldenEyes is a great choice for security professionals looking to secure their web applications.

# Unique Scanner
GoldenEyes stands out for its highly tailored approach, focusing on swift detection and mitigation of high-priority known CVEs (Common Vulnerabilities and Exposures). The tool's functionality is rooted in a customized script designed to efficiently process URLs listed in the urls.txt file. This script meticulously scans each URL for a spectrum of vulnerabilities, ranging from Remote Code Execution (RCE) and Cross-Site Request Forgery (CSRF) to Local File Inclusion (LFI), open redirect, Log4J, Remote File Inclusion (RFI), path traversal, and SQL injection. 

For each vulnerability, GoldenEyes conducts a targeted test, issuing specific HTTP requests and scrutinizing the responses for indicators of exploitation. If a vulnerability is detected, the tool logs the URL as vulnerable in the domain.txt file. Conversely, if no vulnerability is found, a corresponding message affirming the URL's security is recorded. As of the latest update, GoldenEyes has identified a total of 16 vulnerabilities, underscoring its effectiveness in fortifying web applications against potential security risks.

# Main Features
Scans for various web application vulnerabilities, including:

- XSS (Cross-site scripting)

- SSRF (Server-side request forgery)

- XXE (XML external entity)

- Insecure deserialization

- Remote Code Execution via Shellshock (RCE)

- SQL Injection (SQLi)

- Cross-Site Scripting (XSS)

- Cross-Site Request Forgery (CSRF)

- Remote Code Execution (RCE)

- Log4J

- Directory Traversal (DT)

- File Inclusion (FI)

- Sensitive Data Exposure (SDE)

- Server Side Request Forgery (SSRF)

- Shell Injection (SI)

- Broken Access Control (BAC)

- Generates  Quote for Users, Checks if you are connected to the Internet too!

- Utilizes tools such as waybackurls, curl, and others for comprehensive vulnerability assessments
  
- Lightweight and fast, delivering results in real-time directly to the terminal

- Only reports vulnerabilities, making it easy to prioritize and remediate vulnerabilities in a timely manner


# Obtaining required software for running the tool
- waybackurls: This tool can be installed by running `go install github.com/tomnomnom/waybackurls@latest`

- cURL: This tool is commonly pre-installed on Kali Linux and Ubuntu, but can be installed by running `apt-get install curl` on Ubuntu or `brew install curl` on MacOS

- httpx: is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryable http library. To install it: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

- lolcat: `pip install lolcat` for rainbow beauty

# Installation to use
`git clone https://github.com/kyawminthant/GoldenEyes`

`cd GoldenEyes`

`chmod +x GoldenEyes.sh`

`./GoldenEyes.sh`

# References

- [LinuxConfig](https://linuxconfig.org/bash-scripting-tutorial-for-beginners)
- [TerminatorZ](https://github.com/blackhatethicalhacking/TerminatorZ)
- [PluralSight](https://www.pluralsight.com/cloud-guru/labs/aws/write-an-automated-script-to-perform-a-vulnerability-scan-and-log-the-results)
