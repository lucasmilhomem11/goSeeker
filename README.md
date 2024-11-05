```markdown
# 🔍 goSeeker

**goSeeker** is a fast and efficient port scanner built in Go. It allows users to scan specified ports on a target IP address and retrieves detailed information about open ports, including service names and SSL/TLS details.

## Features

- Scans a user-defined range of ports (default: `1-1024`).
- Concurrent scanning with adjustable worker count (default: `1500`).
- Option to save results in JSON format.
- SSL/TLS detection for applicable ports.
- Basic banner grabbing for service identification.
- Clean and colorful terminal output.

## Installation

Make sure you have Go installed on your machine. You can download it from [golang.org](https://golang.org/dl/).

To install the project, clone this repository and navigate to the directory:

```bash
git clone https://github.com/lucasmilhomem11/goSeeker.git
cd goSeeker
```

## Building the Project

There are two ways to run the application: using `go run` or building the binary. Follow these steps to build the binary:

1. **Initialize a Go module (if not already done):**
   ```bash
   go mod init <module-name>
   ```

2. **Build the project:**
   ```bash
   go build -o goSeeker
   ```

### Flags

- `-target`: Specify the target IP address (mandatory).
- `-ports`: Define the port range to scan (e.g., `1-1024`, `80,443`).
- `-timeout`: Set the timeout duration for each port scan (default: `1s`).
- `-workers`: Define the number of concurrent workers (default: `1500`).
- `-output`: Specify an output file for saving results in JSON format.
- `-verbose`: Enable verbose output for detailed logging.

### Usage

Run the scanner with the following command:

```bash
./goSeeker -target <target> -ports <PORT_RANGE> [-timeout <TIMEOUT>] [-workers <NUMBER>] [-output <OUTPUT_FILE>] [-verbose]
```

Alternatively, you can run the application directly without building it:

```bash
go run goSeeker.go -target <target> -ports <port-range> (optional)
```

## Output

The results will be displayed in the terminal and, if specified, saved to the output file in JSON format. The output includes:

- Open ports with their corresponding state.
- Service names associated with each port.
- SSL/TLS version and cipher information for ports that support SSL/TLS.
- Banners retrieved from the services.

## Contributing

Contributions are welcome! If you would like to contribute to **goSeeker**, please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [fatih/color](https://github.com/fatih/color) - for colorful terminal output.
- [zs5460/art](https://github.com/zs5460/art) - for ASCII art support.

## Contact

For any inquiries or suggestions, feel free to open an issue in the repository.

