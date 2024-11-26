import os
import sys
import logging
import yaml
import hashlib
import time
import uuid
from pathlib import Path
from git import Repo
import openai
import json

# ---------------------------
# CONFIGURATION AND LOGGING
# ---------------------------

CONFIG_FILE = "config.yaml"
LOG_FILE = "script.log"
REPO_URL = "https://github.com/mitre-atlas/atlas-navigator-data.git"
DEFAULT_REPO_PATH = "./atlas-navigator-data"
DEFAULT_LOG_LEVEL = logging.DEBUG

# Configure logging
logging.basicConfig(
    level=DEFAULT_LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

# ---------------------------
# UTILITY FUNCTIONS
# ---------------------------

def load_config(file_path):
    """Load and validate the YAML configuration file."""
    if not os.path.exists(file_path):
        logger.error(f"Configuration file not found: {file_path}")
        sys.exit(1)

    with open(file_path, "r") as file:
        config = yaml.safe_load(file)

    required_fields = ["openai_api_key", "repo_path"]
    for field in required_fields:
        if field not in config or not config[field]:
            logger.error(f"Missing required configuration field: {field}")
            sys.exit(1)

    # Add default values for optional fields
    config.setdefault("repo_path", DEFAULT_REPO_PATH)
    config.setdefault("log_level", DEFAULT_LOG_LEVEL)
    return config

def clone_or_update_repo(repo_path):
    """Clone or pull the latest changes from the atlas-navigator-data repository."""
    if os.path.exists(repo_path):
        try:
            repo = Repo(repo_path)
            logger.info(f"Pulling latest changes in {repo_path}")
            repo.remotes.origin.pull()
        except Exception as e:
            logger.error(f"Failed to pull latest changes: {e}")
            sys.exit(1)
    else:
        try:
            logger.info(f"Cloning repository to {repo_path}")
            Repo.clone_from(REPO_URL, repo_path)
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            sys.exit(1)

def compute_hash(data):
    """Compute a hash for tracking changes in TTP data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

# ---------------------------
# CORE FUNCTIONS
# ---------------------------

def process_ttp_data(repo_path, output_path, api_key):
    """Parse TTP data, generate detection reports, and create Sigma rules."""
    ttp_files = list(Path(repo_path).glob("**/*.json"))
    if not ttp_files:
        logger.error("No TTP files found in the repository.")
        return

    openai.api_key = api_key

    for ttp_file in ttp_files:
        logger.info(f"Processing TTP file: {ttp_file}")
        with open(ttp_file, "r") as file:
            try:
                ttp_data = json.load(file)
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid JSON file: {ttp_file}")
                continue

        # Extract relevant data from the JSON
        ttp_name = ttp_data.get("name", "Unknown TTP")
        ttp_description = ttp_data.get("description", "No description available.")
        techniques = ttp_data.get("techniques", [])
        tactics = [tech.get("tactic", "unknown") for tech in techniques if "tactic" in tech]

        # Create output directory
        report_path = Path(output_path) / ttp_file.stem
        report_path.mkdir(parents=True, exist_ok=True)

        # Generate detection report using OpenAI API
        try:
            detection_report = generate_detection_report(ttp_name, ttp_description, techniques, tactics)
        except openai.OpenAIError as e:
            logger.error(f"Failed to generate detection report for {ttp_file.stem}: {e}")
            continue

        # Save the detection report
        with open(report_path / "detection_report.txt", "w") as report_file:
            report_file.write(detection_report)

        # Generate Sigma rule using OpenAI API
        try:
            generate_sigma_rule(ttp_name, ttp_description, techniques, tactics, detection_report, report_path / "rule.yml")
        except openai.OpenAIError as e:
            logger.error(f"Failed to generate Sigma rule for {ttp_file.stem}: {e}")
            continue

def generate_detection_report(name, description, techniques, tactics):
    """Use OpenAI API to generate a detection report."""
    prompt = f"""
    Analyze the following TTP details and generate a detailed detection report that includes:
    1. A summary of the TTP ({name}).
    2. Key log events or fields to monitor based on the techniques ({techniques}).
    3. Recommended detection strategies for the associated tactics ({tactics}).

    Description: {description}
    """
    logger.info("Generating detection report...")
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are an expert in cybersecurity and threat detection."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=800
    )
    return response['choices'][0]['message']['content'].strip()

def generate_sigma_rule(name, description, techniques, tactics, detection_report, output_path):
    """Generate a Sigma rule from the detection report."""
    prompt = f"""
    Create a Sigma rule based on the following detection report:
    - TTP Name: {name}
    - Description: {description}
    - Techniques: {techniques}
    - Tactics: {tactics}

    Detection Report: {detection_report}

    The Sigma rule should be in YAML format.
    """
    logger.info(f"Generating Sigma rule at {output_path}")
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are an expert in threat detection and Sigma rules."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=800
    )
    sigma_rule_content = response['choices'][0]['message']['content'].strip()

    # Remove backticks if present
    if sigma_rule_content.startswith("```yaml"):
        sigma_rule_content = sigma_rule_content.split("```yaml", 1)[1].split("```", 1)[0].strip()

    # Validate YAML content
    try:
        sigma_rule = yaml.safe_load(sigma_rule_content)
        with open(output_path, "w") as file:
            yaml.dump(sigma_rule, file)
        logger.info(f"Sigma rule successfully generated at {output_path}")
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse Sigma rule YAML for {name}: {e}")
        logger.debug(f"Raw content returned by API: {sigma_rule_content}")

# ---------------------------
# MAIN FUNCTION
# ---------------------------

def main():
    """Main function to orchestrate the script."""
    config = load_config(CONFIG_FILE)
    clone_or_update_repo(config["repo_path"])
    process_ttp_data(config["repo_path"], "./output", config["openai_api_key"])

if __name__ == "__main__":
    main()
