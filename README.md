# Hunter-Seeker

Hunter-Seeker is a powerful tool for detecting Web Application Firewalls (WAFs) and performing basic enumeration of web servers. Inspired by the stealth and precision of the Hunter-Seeker from *Dune*, this tool can handle single targets or multiple targets (IPs/domains) and save results in various formats.

## Features

- **Flexible Target Input:**
  - Supports single IPs, domains, or files containing multiple targets.
- **Output Options:**
  - Save results in CSV, JSON, or plain text formats.
- **Basic Enumeration:**
  - Includes ping checks, HTTP headers retrieval, and server banner extraction.
- **WAF Detection:**
  - Identifies WAF presence and type using the [wafw00f](https://github.com/EnableSecurity/wafw00f) library.
- **Multithreading & Rate Limiting:**
  - Optimized for large target lists with adjustable threading and request rate.

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Clone the Repository

```bash
git clone https://github.com/xBurningGiraffe/Misc.Scripts/Python/hunter-seeker.git
cd hunter-seeker
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Basic Command
```bash
python hunter_seeker.py <target> <output_file> [options]
```

### Arguments

| Argument        | Description                                                                                           |
|-----------------|-------------------------------------------------------------------------------------------------------|
| `target`        | Single IP, domain, or path to a file containing multiple targets (one per line).                     |
| `output_file`   | Path to save the output results.                                                                     |

### Options

| Option              | Description                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------|
| `--output_format`   | Specify the output format: `csv`, `json`, or `txt`. Default is `csv`.                             |
| `--threads`         | Number of threads to use for scanning. Default is `5`.                                            |
| `--rate_limit`      | Rate limit (in seconds) between requests to avoid overloading. Default is `1.0`.                  |

### Example Usage

1. **Scan a Single Target:**
   ```bash
   python hunter_seeker.py example.com results.csv --output_format csv
   ```

2. **Scan Multiple Targets from a File:**
   ```bash
   python hunter_seeker.py targets.txt results.json --output_format json --threads 10 --rate_limit 0.5
   ```

3. **Save Results as Plain Text:**
   ```bash
   python hunter_seeker.py example.com results.txt --output_format txt
   ```

## Output Examples

### CSV Output
| Target          | Domain/Subdomain | WAF Detected | WAF Type       | Ping Reachable | HTTP Headers                       | Server Banner       |
|------------------|------------------|--------------|----------------|----------------|-------------------------------------|---------------------|
| example.com     | example.com      | Yes          | Cloudflare     | Yes            | {"Content-Type": "text/html"}      | Apache/2.4.41 (Ubuntu) |

### JSON Output
```json
[
    {
        "Target": "example.com",
        "Domain/Subdomain": "example.com",
        "WAF Detected": "Yes",
        "WAF Type": "Cloudflare",
        "Ping Reachable": "Yes",
        "HTTP Headers": {
            "Content-Type": "text/html"
        },
        "Server Banner": "Apache/2.4.41 (Ubuntu)"
    }
]
```

### TXT Output
```
Target: example.com
Domain/Subdomain: example.com
WAF Detected: Yes
WAF Type: Cloudflare
Ping Reachable: Yes
HTTP Headers: {'Content-Type': 'text/html'}
Server Banner: Apache/2.4.41 (Ubuntu)
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```
