# 🛡️ SentinelAI-Watchdog

## 📝 Description
SentinelAI-Watchdog is an advanced AI-powered system monitoring and malware detection tool that combines machine learning with real-time system surveillance. This comprehensive security solution provides intelligent threat detection, process monitoring, and network activity analysis to protect your system from potential threats.

## ✨ Features
- 🤖 AI-Powered Malware Detection
- 🔍 Real-time Process Monitoring
- 🌐 Network Activity Analysis
- 📊 System Resource Tracking
- 🔒 VirusTotal Integration
- 🤖 Gemini AI Analysis
- 📱 System Tray Integration
- 📈 Performance Metrics

## 🚀 Installation

### 📥 Prerequisites
- Python 3.x
- pip (Python package manager)
- VirusTotal API Key 
- Gemini API Key 

### ⚙️ Required Packages
```bash
pip install psutil requests google-generativeai pystray pillow pefile joblib numpy pandas scikit-learn matplotlib seaborn
```

### ⚙️ Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/samrat-sarkar/SentinelAI-Watchdog.git
   ```

2. Navigate to the project directory:
   ```bash
   cd SentinelAI-Watchdog
   ```

3. Configure VirusTotal API:
   - Replace 'API-KEY' in main.py with your VirusTotal API key

4. Configure Gemini API:
   - Replace 'API-KEY' in main.py with your Gemini API key

## 💻 Usage

### 🎮 Running the Application
1. Execute the main script:
   ```bash
   python main.py
   ```

2. The application will:
   - Start in system tray
   - Begin monitoring system processes
   - Analyze network connections
   - Detect potential threats

### 📋 Available Operations
- Real-time Process Monitoring
- Malware Detection
- Network Analysis
- System Resource Tracking
- Threat Intelligence

## 🛠️ Technical Details
- Built with Python and Machine Learning
- Uses Random Forest Classifier
- PE File Analysis
- Network Traffic Monitoring
- System Resource Tracking
- AI-Powered Threat Detection

## 📊 Model Training
The malware detection model can be trained using:
```bash
python train.py
```
This will:
- Process malware and benign samples
- Train the Random Forest model
- Generate performance metrics
- Save the trained model

## ⚠️ Important Notes
- Keep VirusTotal API key secure
- Regular model updates recommended
- Monitor system resources
- Use alongside other security measures
- Regular backups recommended
- Keep Python environment updated

## 🤝 Contributing
We welcome contributions to improve SentinelAI-Watchdog! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author
- **Samrat Sarkar**
  - LinkedIn: [samratsarkar9999](https://www.linkedin.com/in/samratsarkar9999/)
  - Website: [samratsarkar.in](https://samratsarkar.in/)

## 📞 Support
If you encounter any issues or have questions, please:
1. Check the existing issues
2. Create a new issue with detailed information
3. Include system specifications and error messages

---

**SentinelAI-Watchdog - Intelligent System Protection** 🛡️
