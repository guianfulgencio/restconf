"""
Script to git push the CLI running configuration of PHHQ device
"""
import git
from datetime import datetime
from rich import print as rprint

# Initialize git repo phhq_device_configurations
repo = git.Repo('phhq_device_configurations')
repo.config_writer().set_value("user", "name", "Russel Jude Garcia").release()
repo.config_writer().set_value("user", "email", "rugm@chevron.com").release()
repo.git.add('.')

# Git commit and push
date = datetime.now().strftime("%Y %B %d, %H:%M:%S")
repo.index.commit(f"{date} - RESTCONF change")
repo.git.push()

rprint("✅ Repo phhq_device_configurations has been updated")
