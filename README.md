# File-Analyzer
Performed file analysis, including memory files.
# README

## Forensic Analysis Automation Script

### Overview
This Bash script automates forensic analysis tasks by integrating tools like **Volatility**, **Binwalk**, **Bulk Extractor**, and **Foremost**. The script performs memory analysis, file carving, and registry extraction to streamline digital forensic investigations. Logs are maintained throughout the process for audit and reporting purposes.

### Features
- **Memory Analysis with Volatility:**
  - Extract process lists, network connections, and registry hives.
  - Analyze SAM file for usernames and SOFTWARE registry for executables.
  - Automatically identifies the memory profile based on the provided file.

- **File Carving and Data Extraction:**
  - Extract embedded files using **Binwalk**, **Bulk Extractor**, and **Foremost**.
  - Identify and extract PCAP files and executable files.
  - Perform string searches for specific keywords (e.g., `password`, `username`).

- **Comprehensive Logging:**
  - Logs all actions and results into a centralized log file for reporting and auditing.

- **Automated Environment Setup:**
  - Installs missing tools if not already present.
  - Organizes output into structured directories for easy access.

### Prerequisites
Ensure the following tools are installed:
- **Volatility**
- **Binwalk**
- **Bulk Extractor**
- **Foremost**
- **Strings**

The script checks and installs these tools automatically if missing.

### Directory Structure
The script organizes output into the following directories:
```
forensic_case/
├── binwalk
├── bulk_extractor
├── foremost
├── volatility
└── strings
```

### Usage
1. Run the script as **root** to ensure necessary permissions:
   ```bash
   sudo bash ./FileAnalyzer.sh
   or
   sudo su root
   bash ./FileAnalyzer.sh
   ```

2. When prompted, provide the full path to the file to be analyzed:
   ```
   Please enter a full path to the file you would like to investigate:
   /path/to/file.img
   ```

3. The script performs the following:
   - Checks if the file exists.
   - Creates necessary directories for the analysis.
   - Installs required tools if missing.
   - Executes file carving, memory analysis, and registry extraction.

4. All extracted data and logs are stored in the `forensic_case/` directory.

### Output
- **Log File:**
  - `forensic_case/script_log.txt` contains detailed logs of all performed actions.

- **Zipped Results:**
  - The final output is compressed into `forensic_case.zip` for easy sharing and storage.

### Key Commands and Functions
#### Memory Analysis (`VOLATILITY` function):
- Identify memory profile:
  ```bash
  vol -f <file> imageinfo
  ```
- Extract process lists:
  ```bash
  vol -f <file> --profile=<profile> pslist
  ```
- Extract registry hives:
  ```bash
  vol -f <file> --profile=<profile> hivelist
  ```

#### File Carving (`CARVERS` function):
- Analyze files with Binwalk:
  ```bash
  binwalk <file> -o <output_directory>
  ```
- Extract strings:
  ```bash
  strings <file> | grep -i <keyword>
  ```

### Pay ATTANTION
- Ensure the script is run in an environment with sufficient storage, as extracted files and logs can be large.
- The script assumes the Volatility binary is located at `$HOME/vol/vol`. Soon a vol tool will be easily uploaded with a change to the script. 
