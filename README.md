Provided a website base url, the script crawls through the url and all of its sub-links to find basic security vulnerabilities. 
It checks for 
  1. potential outdated softwares
  2. forms with security vulnerabilities
  3. unsecured HTTP headers and logs any issues found.

--Steps to Run the Code--
Clone the repo into your local device. Switch to prject directory. Execute python app.py. Enter url of the desired website and wait for the crawler to finish.

The program limits the vulnerabilities check to a few functionalities but is scalable for future enhancements which may include furhter checks like Input validation, SSL/TLS configuration checks, Information disclosure detection.


