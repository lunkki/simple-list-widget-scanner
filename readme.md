  
  

# ServiceNow Simple-List Widge Misconfiguration Scanner in Go

## Overview

This Go-based tool scans for misconfigurations in the **ServiceNow** **widget-simple-list** widget. It helps identify instances that may be vulnerable to data exposure due to incorrect settings.

  
## Important Note

For comprehensive details on the attack technique and potential exploitation methods, refer to the [technical documentation available here](https://www.enumerated.ie/servicenow-data-exposure).

## Pre-requisites

- Go 1.x (Download and install from [here](https://golang.org/dl/))

## Usage

1. Clone the repository to your local machine.

2. Navigate to the directory containing `list-scan.go`.

3. Execute the script using the Go command line:


###  Single URL

```bash

go run list-scan.go --url https://redacted.service-now.com

```

  

### Example Output

If the target instance is vulnerable, you'll receive output similar to the following:

```bash

https://redacted.service-now.com/api/now/sp/widget/widget-simple-list?t=incident is EXPOSED, and LEAKING data. Check ACLs ASAP.

```

Data fetched from exposed tables will be saved in a separate JSON file within a directory named after the ServiceNow instance's identifier.

  

> **Note:** A table may be public but not necessarily expose sensitive information. It is critical to verify whether the disclosed data is confidential before proceeding with any action.

## Credits and Acknowledgments

This tool is a Go-based fork of the original Python scanner found [here](https://github.com/bsysop/servicenow). A heartfelt thanks to the original authors and contributors of the Python tool:

- [Lauri Alakulppi](https://www.linkedin.com/in/lauri-alakulppi-81079a143/) - Creator of this tool
- [bsysop](https://twitter.com/bsysop) - Original tool creator.
- [Aaron Costello](https://twitter.com/ConspiracyProof) - Researcher who detailed the technical aspects and exploitation method. [Website](https://www.enumerated.ie/)
- [Others](https://github.com/bsysop/servicenow) - Additional contributors from the Python tool.

The development of this Go version was inspired by the structure, concept, and functionality of the Python project. This version is intended to provide a similar utility in the Go programming environment.

## Disclaimer

This tool is meant for educational purposes and ethical testing only. The authors are not liable for any misuse or potential damage arising from its use. Please utilize the tool responsibly and legally.

