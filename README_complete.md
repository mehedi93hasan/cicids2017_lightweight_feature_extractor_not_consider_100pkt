CICIDS2017 Complete Feature Extractor
Extract all 78 official CICIDS2017 features from PCAP files with automatic EXE generation via GitHub Actions.

🚀 Quick Start - Create EXE on GitHub
Step 1: Upload to GitHub

Go to GitHub.com and sign in
Click "+" (top-right) → "New repository"
Name: cicids2017-extractor (or any name you want)
Select: ✅ Public (required for free Actions)
Click: "Create repository"


Step 2: Upload Files
You need to upload 3 files:
Method A: Web Upload (Easiest)

On your empty repository page, click "uploading an existing file"
Upload these 3 files (drag and drop):

main.py
requirements.txt
README.md (this file)


Click "Commit changes"
Create workflow folder:

Click "Add file" → "Create new file"
Type filename: .github/workflows/build.yml
Copy-paste the content from build.yml
Click "Commit changes"




Method B: Git Command Line
bash# 1. Download all files to a folder
# 2. Open terminal in that folder

# 3. Initialize git
git init
git add main.py requirements.txt README.md

# 4. Create workflow folder
mkdir -p .github/workflows
# Copy build.yml into .github/workflows/

git add .github/workflows/build.yml

# 5. Commit and push
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main

Step 3: GitHub Automatically Builds EXE
After uploading, GitHub Actions starts automatically!
Watch the build:

Go to "Actions" tab
Click on the running workflow
Wait 5-10 minutes for completion
✅ Green checkmark = Success!


Step 4: Download Your EXE
Once build completes:

Scroll down on the workflow page
Find "Artifacts" section
Click: CICIDS2017-Feature-Extractor
ZIP downloads (~40-60 MB)
Extract to get CICIDS2017_Extractor.exe

Done! You now have a standalone Windows EXE!

📁 Required File Structure
Your GitHub repository should look like this:
your-repo/
├── main.py                    ← Main Python application
├── requirements.txt           ← Python dependencies
├── README.md                  ← This file
└── .github/
    └── workflows/
        └── build.yml          ← GitHub Actions workflow
IMPORTANT: The .github/workflows/build.yml path must be exact!

🎯 Using the EXE

Double-click CICIDS2017_Extractor.exe
Select PCAP file using "Browse" button
(Optional) Select Ground Truth CSV for labeling
Click "EXTRACT 78 FEATURES"
Wait for processing to complete
Output files appear in same folder as EXE

Output Files:

CICIDS2017_78Features_YYYYMMDD_HHMMSS.csv - Feature dataset
Feature_Costs_YYYYMMDD_HHMMSS.csv - Computational costs


🔧 Troubleshooting
❌ Build fails with red X

Click on the failed workflow
Click on "build" job
Read error message
Common fixes:

Make sure main.py exists in repository
Check that repository is Public
Verify .github/workflows/build.yml path is correct




❌ EXE doesn't open
Windows SmartScreen:

Click "More info"
Click "Run anyway"

Windows Defender:

Right-click EXE → Properties
Check "Unblock" → Apply

Still doesn't work:

Check if Windows Defender quarantined it
Try running as Administrator


❌ "No workflow runs"
Make sure:

Repository is Public (not Private)
File is at: .github/workflows/build.yml (exact path)
You pushed to main branch
Go to Settings → Actions → Allow all actions


📊 Features Extracted (78 Total)
Flow Features (5)

Flow Duration, Total Fwd/Bwd Packets, Total Fwd/Bwd Bytes

Packet Length Statistics (12)

Min, Max, Mean, Std for Forward, Backward, Overall packets

Flow Rates (4)

Flow Bytes/s, Packets/s, Fwd Packets/s, Bwd Packets/s

Inter-Arrival Time (14)

IAT statistics for Flow, Forward, Backward

TCP Flags (12)

FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts

Advanced Features (31)

Headers, Ratios, Segments, Bulk Transfer, Subflows, Init Windows, Active/Idle periods


💾 System Requirements
For Building (on GitHub - Automatic):

✅ Free GitHub account
✅ Public repository

For Running EXE:

OS: Windows 10/11 (64-bit)
RAM: 4 GB minimum, 8+ GB recommended
Storage: 100 MB free space
No Python required! (EXE is standalone)


🎓 Ground Truth CSV Format
Optional labeling file with columns:
Required columns (flexible names):

Source IP: source_ip, src_ip, etc.
Source Port: source_port, src_port, etc.
Destination IP: destination_ip, dst_ip, etc.
Destination Port: destination_port, dst_port, etc.
Protocol: protocol, proto
Label: label, attack, attack_type, class

Example:
csvSource IP,Source Port,Destination IP,Destination Port,Protocol,Label
192.168.1.100,443,10.0.0.5,12345,6,DDoS
172.16.0.1,80,10.0.0.10,54321,6,BENIGN

📈 Performance

Speed: 30,000-80,000 packets/second
Memory: Scales with PCAP size
Recommended: Process files < 2 GB for best results


⚙️ Manual Build (Optional)
If you want to build locally instead of using GitHub:
bash# 1. Install Python 3.11
# 2. Install dependencies
pip install -r requirements.txt

# 3. Build EXE
pip install pyinstaller
pyinstaller --onefile --windowed --name "CICIDS2017_Extractor" --collect-all customtkinter --hidden-import=PIL._tkinter_finder main.py

# 4. Find EXE in dist/ folder

📄 License
MIT License - Free to use for research and commercial purposes

🙏 Credits

CICIDS2017 Dataset: Canadian Institute for Cybersecurity
Libraries: Scapy, CustomTkinter, Pandas, NumPy


📧 Support
If you encounter issues:

Check the Troubleshooting section above
Open an Issue on GitHub
Provide error message screenshots


🎉 That's it! You now have a complete CICIDS2017 feature extractor!
Upload these files to GitHub, and the EXE will be built automatically within 10 minutes.
