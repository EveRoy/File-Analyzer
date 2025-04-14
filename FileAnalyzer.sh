#!/bin/bash

set -e  # Exit on error

# === Colors ===
RED='\e[31m'
GREEN='\e[32m'
BLUE='\e[34m'
YELLOW='\e[33m'
NC='\e[0m'  # No color

#Check if the script is run as root for proper permissions.
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[✘] Please run this script as root.${NC}"
    exit 1
fi

#Users path for memory file
read -rp "Enter full path to the memory/disk image file: " file

if [[ ! -f "$file" ]]; then
    echo -e "${RED}[✘] File not found: $file${NC}"
    exit 1
fi

# PATHS
HOME_DIR=$(dirname "$file")
CASE_DIR="$HOME_DIR/forensic_case"
VOL_PATH="$HOME_DIR/vol/vol"
LOG_FILE="$CASE_DIR/script_log.txt"


echo -e "${BLUE}==========================================="
echo -e "🔍 Project Analyzer v1.0"
echo -e "Automated Memory Forensics Script"
echo -e "===========================================${NC}"
mkdir -p "$CASE_DIR"
echo -e "\n${BLUE}[INFO] Logging started at $(date)${NC}" | tee -a "$LOG_FILE"


function VOLATILITY() {
    echo -e "\n${BLUE}===== Volatility Analysis =====${NC}"

    if [[ ! -x "$VOL_PATH" ]]; then
        echo -e "${YELLOW}[!] Volatility is not executable. Fixing...${NC}"
        chmod +x "$VOL_PATH"
    fi
# Checks if Volatility can analyze the file.
    vol_banner=$("$VOL_PATH" -f "$file" imageinfo 2>&1)
    if echo "$vol_banner" | grep -q "Suggested Profile(s): No suggestion"; then
        echo -e "${YELLOW}[!] No suggested profile found. Skipping Volatility.${NC}" | tee -a "$LOG_FILE"
        return
    fi

    PROFILE=$("$VOL_PATH" -f "$file" imageinfo | grep Suggested | awk '{print $4}' | cut -d',' -f1)
    echo -e "${GREEN}[✔] Using profile: $PROFILE${NC}" | tee -a "$LOG_FILE"                            # Sets the profile based on Volatility's suggested profile.
    mkdir -p "$CASE_DIR/volatility"

    "$VOL_PATH" -f "$file" --profile="$PROFILE" pslist | tee "$CASE_DIR/volatility/processes.txt"      # Runs various Volatility commands and saves output.
    "$VOL_PATH" -f "$file" --profile="$PROFILE" connscan | tee "$CASE_DIR/volatility/connections_scan.txt"
    "$VOL_PATH" -f "$file" --profile="$PROFILE" hivelist | tee "$CASE_DIR/volatility/hives.txt"
# Dumps registry information and logs success or failure.
    "$VOL_PATH" -f "$file" --profile="$PROFILE" dumpregistry --dump-dir "$CASE_DIR" \
        | tee "$CASE_DIR/dumpregistry_output.txt"
    if [[ $? -ne 0 ]]; then
        echo -e "${YELLOW}[!] dumpregistry failed. Continuing.${NC}" | tee -a "$LOG_FILE"
    fi
# Extracts specific registry keys for usernames and executables.
    "$VOL_PATH" -f "$file" --profile="$PROFILE" printkey -K "SAM\\Domains\\Account\\Users\\Names" \
        | tee "$CASE_DIR/volatility/SAM_usernames.txt"
    "$VOL_PATH" -f "$file" --profile="$PROFILE" printkey -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run" \
        | tee "$CASE_DIR/volatility/executables_names.txt"

    echo -e "${GREEN}[✔] Volatility analysis complete.${NC}" | tee -a "$LOG_FILE"

    echo -e "\n${BLUE}===== File Extraction Summary =====${NC}"

# Counts extracted files in different directories for summary logging.
    path1=$(ls -la "$CASE_DIR/binwalk" 2>/dev/null | wc -l)
    path2=$(ls -la "$CASE_DIR/bulk_extractor" 2>/dev/null | wc -l)
    path3=$(ls -la "$CASE_DIR/bulk_extractor/"*/ 2>/dev/null | wc -l)
    path4=$(ls -la "$CASE_DIR/bulk_extractor/"*/*/ 2>/dev/null | wc -l)
    path5=$(ls -la "$CASE_DIR/foremost" 2>/dev/null | wc -l)
    path6=$(ls -la "$CASE_DIR/foremost/"*/ 2>/dev/null | wc -l)
    path7=$(ls -la "$CASE_DIR/strings" 2>/dev/null | wc -l)
    path8=$(ls -la "$CASE_DIR/volatility" 2>/dev/null | wc -l)
    path9=$(ls -la "$CASE_DIR" 2>/dev/null | wc -l)

    num=$((path1 + path2 + path3 + path4 + path5 + path6 + path7 + path8 + path9))
    echo "[*] Total number of files extracted: $num" | tee -a "$LOG_FILE"
}

# Begins the analysis process - Executes various forensic carvers and saves their output.
function CARVERS() {
    echo -e "\n${BLUE}===== Running Carving Tools =====${NC}"
    mkdir -p "$CASE_DIR"/{binwalk,bulk_extractor,foremost,strings}

    binwalk "$file" | tee "$CASE_DIR/binwalk/output.txt"
    bulk_extractor "$file" -o "$CASE_DIR/bulk_extractor"
    foremost "$file" -o "$CASE_DIR/foremost"

    echo -e "\n${YELLOW}[!] Looking for .pcap files...${NC}"
    pcap_file=$(find "$CASE_DIR/bulk_extractor" -name "*.pcap" | head -n1)
    if [[ -z "$pcap_file" ]]; then
        echo -e "${YELLOW}[!] No PCAP file found.${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${GREEN}[✔] PCAP found: $pcap_file | Size: $(du -b "$pcap_file" | cut -f1) bytes${NC}" | tee -a "$LOG_FILE"
    fi

    echo -e "${GREEN}[✔] Extracting readable strings...${NC}"
    strings "$file" | grep -i password > "$CASE_DIR/strings/OUTPUTpass.txt"
    echo "[*] Strings with 'password' saved." | tee -a "$LOG_FILE"
    strings "$file" | grep -i username > "$CASE_DIR/strings/OUTPUTuser.txt"
    echo "[*] Strings with 'username' saved." | tee -a "$LOG_FILE"

    exe_path="$CASE_DIR/foremost/exe"
    if [ -d "$exe_path" ]; then
        find "$exe_path" -name "*.exe" > "$exe_path/exe_list.txt"
        while read -r exefile; do
            echo -e "${GREEN}[✔] Found EXE: $exefile${NC} | Size: $(du -b "$exefile" | cut -f1) bytes${NC}" | tee -a "$LOG_FILE"
            strings "$exefile" > "$CASE_DIR/strings/OUTPUT_$(basename "$exefile").txt"
        done < "$exe_path/exe_list.txt"
    fi

    VOLATILITY
}

# Downloads and extracts necessary tools if not already installed.
function INSTALL() {
    echo -e "\n${BLUE}===== Checking & Installing Tools =====${NC}"
    for tool in binwalk bulk_extractor foremost; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${YELLOW}[!] Installing missing tool: $tool${NC}"
            sudo apt install -y "$tool"
        else
            echo -e "${GREEN}[✔] $tool is already installed${NC}"
        fi
    done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOL_PATH="$SCRIPT_DIR/vol/vol"

if [[ ! -f "$VOL_PATH" ]]; then
    echo -e "${YELLOW}[!] Volatility not found. Downloading...${NC}"
    git clone https://github.com/EveRoy/File-Analyzer.git /tmp/vol-repo
    cp -r /tmp/vol-repo/vol "$SCRIPT_DIR"
    rm -rf /tmp/vol-repo

    [[ -f "$VOL_PATH" ]] && echo -e "${GREEN}[✔] Volatility downloaded to: $VOL_PATH${NC}" \
        || { echo -e "${RED}[✘] Failed to download Volatility. Check the GitHub repo.${NC}"; exit 1; }
else
    echo -e "${GREEN}[✔] Volatility already exists at: $VOL_PATH${NC}"
fi

    CARVERS
}

# START
function START() {
    echo -e "${GREEN}[✔] File located. Starting analysis...${NC}"
    INSTALL
 # Zips all extracted files.
    zip_name="forensic_case_$(basename "$file" | cut -d'.' -f1).zip"
    zip -r "$HOME_DIR/$zip_name" "$CASE_DIR" > /dev/null

    echo -e "\n${BLUE}===== Summary Report =====${NC}"
    echo -e "${GREEN}[✔] Analysis complete. Archive saved as: $zip_name${NC}"
    echo -e "${GREEN}[✔] Log saved to: script_log.txt${NC}"
}

START
