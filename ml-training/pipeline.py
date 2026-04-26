import os
import subprocess
import sys

DATASET_REPO = "https://github.com/ggyggy666/DNS-Tunnel-Datasets.git"
DATA_DIR = "./DNS-Tunnel-Datasets"
GO_BINARY = "./pcap-extractor"
CSV_OUTPUT = "dataset.csv"

def run_command(cmd):
    """Executes a shell command and streams the output."""
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(process.stdout.readline, b''):
        sys.stdout.write(line.decode('utf-8'))
    process.wait()
    if process.returncode != 0:
        print(f"Command failed with exit code {process.returncode}")
        sys.exit(1)

def setup_data():
    """Clones the repository if it doesn't exist."""
    if not os.path.exists(DATA_DIR):
        print("Dataset not found. Cloning repository...")
        run_command(f"git clone {DATASET_REPO}")
    else:
        print("Dataset already exists locally. Skipping download.")

    # Clean up any old run data
    if os.path.exists(CSV_OUTPUT):
        os.remove(CSV_OUTPUT)
        print(f"Removed old {CSV_OUTPUT}")

def process_pcaps():
    """Walks the dataset directories and calls the Go binary."""
    # Define which folders map to which labels
    label_map = {
        "normal": 0,
        "tunnel": 1
    }

    for category, label in label_map.items():
        folder_path = os.path.join(DATA_DIR, category)
        if not os.path.exists(folder_path):
            print(f"Warning: Expected folder {folder_path} not found.")
            continue

        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".pcap"):
                    pcap_path = os.path.join(root, file)
                    print(f"\n--- Processing {pcap_path} ---")
                    # Shell out to the Go binary
                    run_command(f"{GO_BINARY} -file {pcap_path} -label {label}")

if __name__ == "__main__":
    print("🚀 Starting DNS Radar Data Pipeline")
    setup_data()
    process_pcaps()
    print(f"\n✅ Pipeline complete. Clean data saved to {CSV_OUTPUT}")