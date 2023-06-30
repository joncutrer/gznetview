# gznetview Network Scanner

This script scans a specified network, discovers hosts, and collects information about each host including IP address, MAC address, host name, and manufacturer. It prints the gathered data in a CSV-like format that can be redirected into a CSV file.

The ability to determine MAC addresses and Manufacturer is limited to scanning a locally attached LAN.  You cannot collect this information from a distant subnet.


## Important Disclaimer

This repo is not considered production ready code, it is more for educational purposes.

This code was developed with the assistance of Chat GPT-4 generative AI. You can read the conversation here.

https://chat.openai.com/share/a5bbe554-57d6-4cd6-83dc-b8e370067737

## Dependencies

- nmap
- scapy
- manuf

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/joncutrer/gznetview.git
   ```

2. Navigate to the cloned repository:
   ```bash
   cd gznetview
   ```

3. Install the dependencies using poetry
   ```bash
   poetry update
   ```


## Usage

To run the script, use the following command:
```bash
poetry run python src\main.py <network>
```

Replace `<network>` with the network you want to scan in CIDR notation (e.g., 192.168.1.0/24).

The script will print the information about discovered hosts in CSV format:
```csv
IP Address, MAC Address, Host Name, Manufacturer
192.168.1.1, 00:11:22:33:44:55, my-router, Netgear
192.168.1.2, 66:77:88:99:AA:BB, my-laptop, Dell
...
```

To save the output to a CSV file, you can redirect the output of the script to a file:

```bash
poetry run python src\main.py <network> > output.csv
```


## License

This project is licensed under the terms of the MIT license.