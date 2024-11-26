# Automating MITRE ATLAS Detection Engineering with Sigma

This repository contains a Python script that automates the generation of detection reports and Sigma rules for TTPs (Tactics, Techniques, and Procedures) in the MITRE ATLAS Navigator dataset. By leveraging the OpenAI GPT model, the script analyzes JSON files from the ATLAS Navigator repository and generates actionable detection reports and Sigma rules.

---

## Features

- **Automated Repository Management**:
  - Clones or updates the MITRE ATLAS Navigator dataset from GitHub.
- **Detection Report Generation**:
  - Analyzes TTP JSON data and generates detailed detection reports using OpenAI's GPT model.
- **Sigma Rule Creation**:
  - Transforms detection reports into Sigma rules tailored for threat detection and incident response.
- **YAML Validation**:
  - Ensures Sigma rules are syntactically valid YAML files.
- **Incremental Processing**:
  - Tracks changes in TTP files to avoid unnecessary reprocessing.

---

## Requirements

- **Python**: 3.8+
- **OpenAI GPT API Key**: Required to generate detection reports and Sigma rules.
- **Dependencies**: Install via `pip` (see [Installation](#installation)).

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/Automating-MITRE-ATLAS-Detection-Engineering.git
   cd Automating-MITRE-ATLAS-Detection-Engineering
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate    # On Windows: .venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `config.yaml` file with the following structure:
   ```yaml
   openai_api_key: "your-openai-api-key"
   repo_path: "./atlas-navigator-data"
   ```

---

## Usage

1. Run the script:
   ```bash
   python script.py
   ```

2. The script will:
   - Clone or update the ATLAS Navigator repository.
   - Process JSON files in the repository.
   - Generate detection reports and Sigma rules in the `./output` directory.

---

## Output Structure

The output directory mirrors the structure of the MITRE ATLAS Navigator repository:

```
output/
├── stix-atlas-attack-enterprise/
│   ├── detection_report.txt
│   ├── rule.yml
├── stix-atlas.json/
│   ├── detection_report.txt
│   ├── rule.yml
...
```

- **`detection_report.txt`**: A detailed report for each TTP.
- **`rule.yml`**: A Sigma rule derived from the detection report.

---

## Logging

Logs are saved in `script.log` and displayed on the console. Logs include:

- Repository update actions.
- Processing details for each TTP file.
- OpenAI API interactions and responses.
- Errors and warnings (e.g., invalid JSON or YAML).

---

## Troubleshooting

- **Error: `Missing required configuration field`**:
  - Ensure the `config.yaml` file is correctly configured with your OpenAI API key and repository path.

- **Error: `Failed to parse Sigma rule YAML`**:
  - Check the raw content returned by the OpenAI API (logged in `script.log`). The Sigma rule may need manual adjustments.

- **Error: `No TTP files found in the repository`**:
  - Verify that the MITRE ATLAS Navigator repository has been cloned correctly.

---

## Contributing

Contributions are welcome! If you encounter issues or have ideas for improvement, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **MITRE ATLAS Navigator**: https://github.com/mitre-atlas/atlas-navigator-data
- **OpenAI GPT API**: https://openai.com/api

---

## Contact

For questions or feedback, please contact [admin@rgrit.us].