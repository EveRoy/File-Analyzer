#!/bin/bash


HOME=$(pwd)                                                                        # Sets the working directory to the current path.
mkdir $HOME/forensic_case                                                          # Creates a directory for the forensic analysis.
LOG_FILE="$HOME/forensic_case/script_log.txt"                                      # Defines the log file location.

echo "Logging started at $(date)" | tee -a "$LOG_FILE"                             # Logs the start time.

function VOLATILITY() {
	echo "------ Starting VOLATILITY at $(date) ------" | tee -a "$LOG_FILE"        # Logs the start time of the VOLATILITY function.

	# Checks if Volatility can analyze the file.
	vol_banner=$($HOME/vol/vol -f "$file" imageinfo 2>&1)
	if echo "$vol_banner" | grep -q "Suggested Profile(s): No suggestion"; then
		echo "[+] File cannot be analyzed with Volatility." | tee -a "$LOG_FILE"
	else
		echo "[+] File can be analyzed with Volatility." | tee -a "$LOG_FILE"

		# Sets the profile based on Volatility's suggested profile.
		PROFILE=$($HOME/vol/vol -f $file imageinfo | grep Suggested | awk '{print $4}' | awk -F ',' '{print $1}')
		echo "---The found profile: $PROFILE "

		# Runs various Volatility commands and saves output.
		echo "[+] Getting processes list from the memory:" | tee -a "$LOG_FILE"
		$HOME/vol/vol -f $file --profile=$PROFILE pslist | tee -a "$HOME/forensic_case/volatility/processes.txt"

		echo "[+] Getting information related to network connections.." | tee -a "$LOG_FILE"
		$HOME/vol/vol -f $file --profile=$PROFILE connscan | tee -a "$HOME/forensic_case/volatility/connections_scan.txt"

		echo "[+] Making an attempt to provide hive list:" | tee -a "$LOG_FILE"
		$HOME/vol/vol -f $file --profile=$PROFILE hivelist | tee -a "$HOME/forensic_case/volatility/hives.txt"

		# Dumps registry information and logs success or failure.
		$HOME/vol/vol -f $file --profile=$PROFILE dumpregistry --dump-dir $HOME/forensic_case | tee -a "$HOME/forensic_case/dumpregistry_output.txt"
		if [ "$?" == "1" ]; then
			echo "Couldn't extract hive list.." | tee -a "$LOG_FILE"
			exit
		else
			# Extracts specific registry keys for usernames and executables.
			echo "[+] Attempting to extract usernames from the SAM file:" | tee -a "$LOG_FILE"
			$HOME/vol/vol -f $file --profile=$PROFILE printkey -K "SAM\\Domains\\Account\\Users\\Names" | tee -a "$HOME/forensic_case/volatility/SAM_usernames.txt"

			echo "[+] Attempting to find executables names from the SYSTEM file:" | tee -a "$LOG_FILE"
			$HOME/vol/vol -f $file --profile=$PROFILE printkey -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run" | tee -a "$HOME/forensic_case/volatility/executables_names.txt"
		fi
	fi

	echo "------ Finished VOLATILITY at $(date) ------" >> "$LOG_FILE"

	# Counts extracted files in different directories for summary logging.
	path1=$(ls -la /home/kali/Desktop/forensic_case/binwalk | wc -l)
	path2=$(ls -la /home/kali/Desktop/forensic_case/bulk_extractor | wc -l)
	path3=$(ls -la /home/kali/Desktop/forensic_case/bulk_extractor/*/ | wc -l)
	path4=$(ls -la /home/kali/Desktop/forensic_case/bulk_extractor/*/*/ | wc -l)
	path5=$(ls -la /home/kali/Desktop/forensic_case/foremost | wc -l)
	path6=$(ls -la /home/kali/Desktop/forensic_case/foremost/*/ | wc -l)
	path7=$(ls -la /home/kali/Desktop/forensic_case/strings | wc -l)
	path8=$(ls -la /home/kali/Desktop/forensic_case/volatility | wc -l)
	path9=$(ls -la /home/kali/Desktop/forensic_case | wc -l)

	num=$((path1 + path2 + path3 + path4 + path5 + path6 + path7 + path8 + path9))
	echo "[*] The number of files extracted is: $num" | tee -a "$LOG_FILE"

	echo "------ Finished Volatility at $(date) ------" | tee -a "$LOG_FILE"
	zip -r $HOME/forensic_case.zip $HOME/forensic_case > /dev/null 2>&1             # Zips all extracted files.
	echo "------ Forensic_case directory has been zipped to forensic_case.zip ------"
}

function CARVERS() {
	echo "------ Starting CARVERS at $(date) ------" | tee -a "$LOG_FILE"

	# Executes various forensic carvers and saves their output.
	binwalk $file -o $HOME/forensic_case/binwalk
	bulk_extractor $file -o $HOME/forensic_case/bulk_extractor
	foremost $file -o $HOME/forensic_case/foremost
	
	echo "[+] Checking for PCAP file...." | tee -a "$LOG_FILE"
	ls $HOME/forensic_case/bulk_extractor | grep .pcap | tee -a "$LOG_FILE"
	if [ "$?" == "1" ]; then
		echo "Couldn't find a PCAP file..." | tee -a "$LOG_FILE"
		exit
	else
		echo "PCAP file was found! Location: $HOME/forensic_case/bulk_extractor" | tee -a "$LOG_FILE"
		echo "File size: $(sudo ls -la $HOME/forensic_case/bulk_extractor | grep .pcap | awk '{print $5}') bytes" | tee -a "$LOG_FILE"
	fi
	
	# Extracts strings with specific keywords (e.g., passwords, usernames).
	echo "Extracting human readable strings.." | tee -a "$LOG_FILE"
	strings $file | grep -i password >> $HOME/forensic_case/strings/OUTPUTpass.txt | echo " [*] Strings password output is saved..." | tee -a "$LOG_FILE"
	strings $file | grep -i username >> $HOME/forensic_case/strings/OUTPUTusename.txt | echo " [*] Strings usernames output is saved..." | tee -a "$LOG_FILE"

	# Searches for EXE files and processes them if found.
	ls $HOME/forensic_case/foremost/exe | grep .exe | tee -a "$LOG_FILE"
	if [ "$?" == "1" ]; then
		echo "Couldn't find an EXE file..." | tee -a "$LOG_FILE"
		exit
	else
		sudo ls -la $HOME/forensic_case/foremost/exe | grep .exe | awk '{print $NF}' > $HOME/forensic_case/foremost/exe/exe_names.txt

		for exefile in $(cat $HOME/forensic_case/foremost/exe/exe_names.txt); do
			echo "EXE file was found! Location: $HOME/forensic_case/foremost/exe/$exefile" | tee -a "$LOG_FILE"
		
			file_size=$(sudo ls -la $HOME/forensic_case/foremost/exe/$exefile | awk '{print $5}')
			echo "File size: $file_size bytes" | tee -a "$LOG_FILE"

			strings $HOME/forensic_case/foremost/exe/$exefile > $HOME/forensic_case/strings/OUTPUT_$exefile.txt
			echo " [*] Strings output on exe file saved to OUTPUT_$exefile.txt" | tee -a "$LOG_FILE"
		done
	fi
	
	VOLATILITY 
}

function INSTALL() {
	echo "------ Starting INSTALL at $(date) ------" >> "$LOG_FILE"

	# Downloads and extracts necessary tools if not already installed.
	
	tools=("binwalk" "bulk_extractor" "foremost")
	for tool in "${tools[@]}"; do
		if which "$tool" > /dev/null; then
			echo "$tool is already installed" | tee -a "$LOG_FILE"
		else
			echo "$tool is not installed, installing now..." >> "$LOG_FILE"
			sudo apt install -y "$tool" >> "$LOG_FILE"
			echo "$tool has been installed" >> "$LOG_FILE"
		fi
	done
	
	echo "------ Finished INSTALL at $(date) ------" >> "$LOG_FILE"
	CARVERS 
}

function START() {
	echo "------ Starting START at $(date) ------" | tee -a "$LOG_FILE"

	# Checks if the script is run as root for proper permissions.
	user=$(whoami)
	if [ "$user" == "root" ]; then
		echo "You are root.. continuing.." | tee -a "$LOG_FILE"
	# Prompts user to specify a file to analyze.
	echo "Please enter a full path to the file you would like to investigate:"
	read file
	# Checking if the file exists.
	if locate $file > /dev/null; then
			echo "$file exists, continuing...."
		else
			echo "$file is not found...exiting..."
			exit 
	fi 
	
	echo "Creating a directory for the case..." | tee -a "$LOG_FILE"
	mkdir $HOME/forensic_case/binwalk $HOME/forensic_case/bulk_extractor $HOME/forensic_case/foremost $HOME/forensic_case/volatility $HOME/forensic_case/strings > /dev/null 2>&1
	
	INSTALL 
	else
		echo "You are not root.. exiting..." | tee -a "$LOG_FILE"
		exit
	fi
	
	
	echo "------ Finished at $(date) ------" | tee -a "$LOG_FILE"
}

START   # Begins the analysis process
