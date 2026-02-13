# Real-time DDoS Detection using Machine Learning

## Description

This project implements a real-time Distributed Denial of Service (DDoS) detection tool using machine learning techniques. The tool analyzes network traffic in real-time to identify and alert on potential DDoS attacks targeting a specified IP address.

The system uses Scapy for packet sniffing and a trained machine learning model (based on features extracted from network flows) to classify traffic as normal or malicious. It provides continuous monitoring, logging, and alerting capabilities.

## Features

- **Real-time Detection**: Continuously monitors network traffic and analyzes it in 5-second windows.
- **Machine Learning Based**: Utilizes a trained model to detect anomalous patterns indicative of DDoS attacks.
- **Flow-based Analysis**: Tracks network flows with timeouts to maintain state.
- **Alerting System**: Provides console alerts and logs attacks to a file with cooldown periods.
- **Statistics Tracking**: Counts packets, alerts, and tracks top source IPs.
- **Configurable Thresholds**: Adjustable alert threshold (default 0.80) and cooldown periods.

## Prerequisites

- Python 3.x
- Root/administrator privileges (required for packet sniffing)
- Trained model file (`ddos_model-latest-1.pkl`) - generated from the training notebook

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Souvik65/Real-time-DDoS-Dection-using-ML.git
   cd Real-time-DDoS-Dection-using-ML
   ```

2. Install required dependencies:
   ```bash
   pip install scapy numpy pandas joblib scikit-learn
   ```

3. (Optional) If you need to train the model yourself, open and run the `training-model-for-ddos.ipynb` notebook.

## Usage

1. Ensure you have the trained model file (`ddos_model-latest-1.pkl`) in the same directory as `detect.py`.

2. Run the detection script with administrator privileges:
   ```bash
   sudo python3 detect.py
   ```

3. Enter the target IP address you want to monitor for DDoS attacks.

4. Select the network interface to sniff on from the list provided.

5. The tool will start monitoring traffic. It will display:
   - Packet counts
   - Flow information
   - Alerts when DDoS is detected
   - Summary statistics every 5 seconds

6. Press Ctrl+C to stop monitoring.

## Configuration

You can modify the following parameters in `detect.py`:

- `TIME_WINDOW`: Analysis window in seconds (default: 5)
- `FLOW_TIMEOUT`: Flow timeout in seconds (default: 15)
- `ALERT_THRESHOLD`: Probability threshold for alerts (default: 0.80)
- `ALERT_COOLDOWN`: Minimum time between alerts in seconds (default: 60)
- `MODEL_PATH`: Path to the trained model file

## Files

- `detect.py`: Main detection script
- `training-model-for-ddos.ipynb`: Jupyter notebook for training the ML model
- `ddos_model-latest-1.pkl`: Trained machine learning model (not included, generate from notebook)
- `ddos_attack_log.txt`: Log file for detected attacks (created automatically)

## Model Training

To train your own model:

1. Open `training-model-for-ddos.ipynb` in Jupyter.
2. Follow the steps to load data, preprocess, train, and save the model.
3. Ensure the saved model file is named `ddos_model-latest-1.pkl`.

## Warning

This tool requires network sniffing capabilities and should be used responsibly. Ensure you have permission to monitor the network traffic. Do not misuse this tool for unauthorized activities.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
