import os
import sys
import subprocess
import hashlib
import requests
from pathlib import Path
from datetime import datetime
import csv
import shutil
# VirusTotal API Key
VIRUSTOTAL_API_KEY = "Your_API_Key"

def get_partition_offset(raw_image, mmls_path):
    try:
        result = subprocess.run([str(mmls_path), raw_image], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "FAT32" in line or "NTFS" in line or "EXT" in line:  # Add more types as needed
                parts = line.split()
                return int(parts[2])  # Start offset
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run mmls: {e}")
        sys.exit(1)
    print("Error: Could not determine partition offset.")
    sys.exit(1)

def query_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "hash": hash_value,
                "malicious": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
                "undetected": data["data"]["attributes"]["last_analysis_stats"]["undetected"],
            }
        else:
            print(f"Warning: Failed to query VirusTotal for {hash_value} (status code: {response.status_code})")
            return {"hash": hash_value, "malicious": "N/A", "undetected": "N/A"}
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return {"hash": hash_value, "malicious": "N/A", "undetected": "N/A"}

def analyze_evtx_files(evtx_dir, chainsaw_path, results_file):
    """
    Analyze extracted EVTX files using Chainsaw.
    """
    try:
        print("Analyzing EVTX files using Chainsaw...")
        chainsaw_cmd = [
            chainsaw_path,
            "hunt",
            str(evtx_dir),
            "-s", r"Input_Path",  # Replace with the actual path to Chainsaw rules
            "--mapping", r"Input_Path",  # Replace with the actual mapping file path
            "--output", str(results_file),
        ]
        subprocess.run(chainsaw_cmd, check=True)
        print(f"Chainsaw analysis completed. Results saved to {results_file}.")
    except subprocess.CalledProcessError as e:
        print(f"Error running Chainsaw: {e}")
        sys.exit(1)

def create_unique_output_directory(script_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = script_dir / f"Output_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def analyze_pcap_files_with_suricata(pcap_dir, suricata_path, suricata_output_dir):
    """
    Analyze all PCAP files in the specified directory using suricata.
    """
    try:
        print("Analyzing PCAP files using Suricata...")
        suricata_output_dir.mkdir(parents=True, exist_ok=True)
        
        for pcap_file in pcap_dir.rglob("*.pcap"):
            if pcap_file.is_file():
                # Generate a unique output file for each PCAP
                output_file = suricata_output_dir / f"{pcap_file.stem}_suricata_output.txt"
                
                # Run Snort for the current PCAP file
                suricata_cmd = [
                    suricata_path,
                    "-r", str(pcap_file),
                    "-l", str(suricata_output_dir)
                ]
                
                print(f"Running suricata on {pcap_file}...")
                result = subprocess.run(suricata_cmd, capture_output=True, text=True)
                
                # Save Snort's output to a text file
                with output_file.open("w") as f:
                    f.write(result.stdout)
                
                if result.returncode != 0:
                    print(f"Warning: suricata exited with errors for {pcap_file}. Check the output file for details.")
                else:
                    print(f"suricata analysis completed for {pcap_file}. Results saved to {output_file}.")
        
        print(f"All PCAP files analyzed. Results saved to {suricata_output_dir}.")
    except Exception as e:
        print(f"Error running suricata: {e}")
        sys.exit(1)

def organize_final_results(output_dir):
    """Moves final results to a single directory and deletes all other files."""
    final_results_dir = output_dir / "final_results"
    final_results_dir.mkdir(exist_ok=True)

    # Define the result files to keep
    files_to_keep = {
        "virustotal_results.csv": output_dir / "virustotal_results.csv",
        "chainsaw_results.txt": output_dir / "chainsaw_results.txt",
        "fast.log": output_dir / "suricata_results" / "fast.log",
        "file_hashes.txt": output_dir / "file_hashes.txt"
    }

    # Move required files to final_results
    for filename, file_path in files_to_keep.items():
        if file_path.exists():
            shutil.move(str(file_path), str(final_results_dir / filename))

    # Delete everything else in the output directory
    for item in output_dir.iterdir():
        if item != final_results_dir:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    print(f"Final results saved in: {final_results_dir}")

def main(raw_image):
    # Create a unique output directory
    script_dir = Path(__file__).parent
    output_dir = create_unique_output_directory(script_dir)
    recovered_files_dir = output_dir / "recovered_files"
    evtx_files_dir = output_dir / "evtx_files"
    pcap_files_dir = output_dir / "pcap_files"
    hash_output_file = output_dir / "file_hashes.txt"
    virustotal_output_file = output_dir / "virustotal_results.csv"
    chainsaw_output_file = output_dir / "chainsaw_results.txt"
    suricata_output_dir = output_dir / "suricarta_results"

    # Set paths to binaries and other required files
    chainsaw_path = r"Input_Path"
    suricata_path = r"Input_Path"
    tsk_recover_path = r"Input_Path"
    mmls_path = r"Input_Path"

    if not os.path.exists(tsk_recover_path) or not os.path.exists(mmls_path) or not os.path.exists(chainsaw_path):
        print(f"Error: Required binaries not found.")
        sys.exit(1)

    # Determine the partition offset
    print("Determining partition offset...")
    offset = get_partition_offset(raw_image, mmls_path)
    print(f"Partition offset determined: {offset}")

    # Recover all files from the raw image
    print("Recovering files from the raw image...")
    recovered_files_dir.mkdir(exist_ok=True)
    tsk_recover_cmd = [str(tsk_recover_path), "-o", str(offset), "-a", raw_image, str(recovered_files_dir)]
    try:
        subprocess.run(tsk_recover_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to recover files from the raw image: {e}")
        sys.exit(1)

    print(f"Files successfully recovered to {recovered_files_dir}")

    # Present options to the user
    print("\nSelect an option to proceed:")
    print("1. VirusTotal + Hash Combination")
    print("2. EVTX + Chainsaw Combination")
    print("3. Extract PCAP + suricata Analysis")
    print("4. All")
    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice in {"1", "4"}:
        # Generate hash values for all recovered files
        print("Generating hash values for all recovered files...")
        hashes = []
        with open(hash_output_file, "w") as hash_file:
            for file_path in recovered_files_dir.rglob("*"):
                if file_path.is_file():
                    md5_hash = hashlib.md5()
                    with open(file_path, "rb") as f:
                        while chunk := f.read(8192):
                            md5_hash.update(chunk)
                    hash_value = md5_hash.hexdigest()
                    hashes.append(hash_value)
                    hash_file.write(f"{hash_value}  {file_path}\n")

        print(f"Hash values successfully written to {hash_output_file}")

        # Query VirusTotal for each hash
        print("Querying VirusTotal for hash information...")
        with open(virustotal_output_file, "w", newline="") as csvfile:
            csvwriter = csv.DictWriter(csvfile, fieldnames=["hash", "malicious", "undetected"])
            csvwriter.writeheader()
            for hash_value in hashes:
                result = query_virustotal(hash_value)
                csvwriter.writerow(result)

        print(f"VirusTotal results successfully written to {virustotal_output_file}")

    if choice in {"2", "4"}:
        # Extract EVTX files from the recovered files
        print("Extracting EVTX files...")
        evtx_files_dir.mkdir(exist_ok=True)
        for file_path in recovered_files_dir.rglob("*.evtx"):
            if file_path.is_file():
                target_path = evtx_files_dir / file_path.name
                target_path.write_bytes(file_path.read_bytes())

        print(f"EVTX files successfully extracted to {evtx_files_dir}")

        # Analyze the extracted EVTX files with Chainsaw
        if any(evtx_files_dir.iterdir()):
            analyze_evtx_files(evtx_files_dir, chainsaw_path, chainsaw_output_file)
        else:
            print("No EVTX files found for analysis.")

    if choice == "4" or choice == "3":
    # Extract PCAP files
        print("Extracting PCAP files...")
        pcap_files_dir.mkdir(exist_ok=True)
        for file_path in recovered_files_dir.rglob("*.pcap"):
            if file_path.is_file():
                target_path = pcap_files_dir / file_path.name
                target_path.write_bytes(file_path.read_bytes())

    print(f"PCAP files successfully extracted to {pcap_files_dir}")

    # Analyze the extracted PCAP files with suricata
    if any(pcap_files_dir.iterdir()):
        analyze_pcap_files_with_suricata(
            pcap_files_dir,
            suricata_path="Input_Path",
            suricata_output_dir = output_dir / "suricata_results"
        )
    else:
        print("No PCAP files found for analysis.")

    organize_final_results(output_dir)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_hashes.py <raw_image_file>")
        sys.exit(1)

    raw_image = sys.argv[1]
    main(raw_image)
