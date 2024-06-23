# VirusTotal Domain Scanner

This PowerShell script allows you to scan domains using the VirusTotal API and saves the results to a CSV file. It includes a graphical user interface (GUI) to input your API key, select input and output files, and choose between light and dark modes.

## NOTE: 
- VT free API allows only 4 lookups/min. Therefore, this script will delay scan for 60 seconds after every 4 lookups.
- VT allows only 500 lookups/day for the free API. 

## Features
- **API Key Input**: Enter your VirusTotal API key directly in the GUI.
- **File Selection**: Browse and select input CSV file containing domains and output CSV file to save results.
- **Light/Dark Mode**: Choose between light and dark themes for the GUI.
- **Progress Bar**: Displays progress of the scanning process.
- **Status Updates**: Real-time updates on the scanning status, running time, and delay time.
- **Detailed Results**: Saves results including the number of malicious vendors, community score, creation date, last analysis date, and a permalink to VirusTotal.

## Usage
1. Download and run the PowerShell file.
2. Enter your VirusTotal API key.
3. Browse and select the input CSV file containing the domains to scan.
4. Browse and select the output CSV file to save the results.
5. Click OK to start the scanning process.
