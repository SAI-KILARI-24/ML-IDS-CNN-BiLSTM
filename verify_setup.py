import os
import sys

# Define all required directories
REQUIRED_DIRS = [
    "dataset",
    "preprocessing",
    "models",
    "training",
    "evaluation",
    "explainability",
    "packet_processing",
    "dashboard",
    "pcap",
    "saved_models"
]

def verify_directories():
    print("=== Checking Project Directory Structure ===")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    all_ok = True
    for folder in REQUIRED_DIRS:
        folder_path = os.path.join(base_dir, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, exist_ok=True)
            print(f"[CREATED] Directory: {folder}/")
        else:
            print(f"[EXISTS] Directory: {folder}/")
    return all_ok

def verify_python_packages():
    print("\n=== Checking Installed Python Packages ===")
    packages = [
        "scapy",
        "numpy",
        "pandas",
        "sklearn",
        "tensorflow",
        "shap",
        "streamlit",
        "matplotlib",
        "seaborn"
    ]
    
    missing = []
    for pkg in packages:
        try:
            __import__(pkg)
            print(f"[OK] {pkg} is installed.")
        except ImportError:
            print(f"[MISSING] {pkg} is NOT installed.")
            missing.append(pkg)
            
    if missing:
        print("\n[WARNING] Some packages are missing. Run:")
        print("  pip install -r requirements.txt")
    else:
        print("\n[SUCCESS] All core packages are installed successfully!")

if __name__ == "__main__":
    verify_directories()
    verify_python_packages()
