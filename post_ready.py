#!/usr/bin/env python3
#
# PostReady v2.7 - System Preparation Tool
# Author: Julian Loontjens
# Date: 2026-02-12
#

import npyscreen
import subprocess
import re
import os
import logging
import shutil
import sys
import time
from pathlib import Path

# --- CONFIGURATIE ---
LOG_FILE = "/var/log/postready.log"
# MOTD Instellingen
MOTD_REPO = "https://github.com/JulienLoon/julianloontjens-motd.git"
MOTD_TARGET_DIR = "/etc/essentials/julianloontjens-motd"
MOTD_SCRIPT_PATH = os.path.join(MOTD_TARGET_DIR, "install.sh")
MOTD_UNINSTALL_PATH = os.path.join(MOTD_TARGET_DIR, "uninstall.sh")

# Setup Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class PostReadyForm(npyscreen.FormBaseNew):
    def create(self):
        # --- 1. DE HOOFDTITEL (Bovenin) ---
        title = "PostReady v2.7 - System Preparation Tool"
        center_x_title = int((self.columns - len(title)) / 2)
        
        self.add(
            npyscreen.FixedText, 
            value=title, 
            editable=False, 
            rely=0,
            relx=center_x_title, 
            color="STANDOUT"
        )

        # --- 2. ASCII ART HEADER (Daaronder) ---
        logo_lines = [
            r" ____           _   ____                _       ",
            r"|  _ \ ___  ___| |_|  _ \ ___  __ _  __| |_   _ ",
            r"| |_) / _ \/ __| __| |_) / _ \/ _` |/ _` | | | |",
            r"|  __/ (_) \__ \ |_|  _ <  __/ (_| | (_| | |_| |",
            r"|_|   \___/|___/\__|_| \_\___|\__,_|\__,_|\__, |",
            r"                                          |___/ "
        ]
        
        subtitle = "by Julian Loontjens"

        current_y = 2 
        for line in logo_lines:
            center_x = int((self.columns - len(line)) / 2)
            if center_x < 0: center_x = 0
            
            self.add(
                npyscreen.FixedText,
                value=line,
                editable=False,
                rely=current_y,
                relx=center_x,
                color="GOOD"
            )
            current_y += 1

        center_sub = int((self.columns - len(subtitle)) / 2)
        self.add(
            npyscreen.FixedText,
            value=subtitle,
            editable=False,
            rely=current_y,
            relx=center_sub,
            color="CYAN"
        )

        self.add(npyscreen.FixedText, value=f"Log output: {LOG_FILE}", editable=False, rely=current_y + 2, relx=2, color="WARNING")

        row = current_y + 4

        # --- SECTIE: FEATURES ---
        self.add(npyscreen.FixedText, value="[ FEATURES ]", rely=row, relx=2, color="LABEL")
        row += 1
        self.chk_motd = self.add(npyscreen.Checkbox, name="Install/Update Custom MOTD", value=True, rely=row, relx=4)
        row += 1
        self.chk_motd_uninstall = self.add(npyscreen.Checkbox, name="Uninstall Custom MOTD", value=False, rely=row, relx=4)
        row += 2

        # --- SECTIE: CLEANUP & SYSPREP ---
        self.add(npyscreen.FixedText, value="[ CLEANUP / SYSPREP ]", rely=row, relx=2, color="LABEL")
        row += 1
        self.chk_history = self.add(npyscreen.Checkbox, name="Clear Bash History", value=True, rely=row, relx=4)
        row += 1
        self.chk_logs = self.add(npyscreen.Checkbox, name="Truncate /var/log/*", value=True, rely=row, relx=4)
        row += 1
        self.chk_apt = self.add(npyscreen.Checkbox, name="APT Clean & Autoremove", value=True, rely=row, relx=4)
        row += 1
        self.chk_update = self.add(npyscreen.Checkbox, name="APT Update & Upgrade", value=False, rely=row, relx=4)
        row += 1
        self.chk_ssh = self.add(npyscreen.Checkbox, name="Regen SSH Host Keys", value=False, rely=row, relx=4)
        row += 1
        self.chk_machineid = self.add(npyscreen.Checkbox, name="Reset Machine-ID", value=False, rely=row, relx=4)
        row += 1
        self.chk_cloudinit = self.add(npyscreen.Checkbox, name="Clean Cloud-init (VM Template)", value=False, rely=row, relx=4)
        row += 2

        # --- SECTIE: NETWORK ---
        self.add(npyscreen.FixedText, value="[ NETWORK ]", rely=row, relx=2, color="LABEL")
        row += 1
        
        self.detected_iface = self.get_default_interface()
        self.add(npyscreen.FixedText, value=f"Interface: {self.detected_iface}", rely=row, relx=4, color="GREEN")
        row += 1
        
        self.chk_dhcp = self.add(npyscreen.Checkbox, name="Enable DHCP", value=True, rely=row, relx=4)
        self.chk_dhcp.when_value_edited = self.toggle_static_fields
        row += 1
        
        self.field_ip = self.add(npyscreen.TitleText, name="IP/CIDR:", rely=row, relx=4, hidden=True, begin_entry_at=14)
        self.field_gw = self.add(npyscreen.TitleText, name="Gateway:", rely=row+1, relx=4, hidden=True, begin_entry_at=14)
        self.field_dns = self.add(npyscreen.TitleText, name="DNS:", rely=row+2, relx=4, hidden=True, begin_entry_at=14)
        row += 4

        # --- SECTIE: SYSTEM SETTINGS ---
        self.add(npyscreen.FixedText, value="[ SETTINGS ]", rely=row, relx=2, color="LABEL")
        row += 1
        self.field_hostname = self.add(npyscreen.TitleText, name="Hostname:", rely=row, relx=4, begin_entry_at=14)
        row += 1
        self.field_user = self.add(npyscreen.TitleText, name="New User:", rely=row, relx=4, begin_entry_at=14)
        row += 1
        self.field_timezone = self.add(npyscreen.TitleText, name="Timezone:", rely=row, relx=4, begin_entry_at=14, value="Europe/Amsterdam")
        row += 1
        self.field_locale = self.add(npyscreen.TitleText, name="Locale:", rely=row, relx=4, begin_entry_at=14, value="en_US.UTF-8")
        row += 2

        # --- CONTROLS ---
        btn_start_x = int(self.columns / 2) - 16
        btn_exit_x = int(self.columns / 2) + 6

        self.btn_start = self.add(npyscreen.ButtonPress, name="[ APPLY ]", rely=row, relx=btn_start_x, when_pressed_function=self.on_start)
        self.btn_exit = self.add(npyscreen.ButtonPress, name="[ QUIT ]", rely=row, relx=btn_exit_x, when_pressed_function=self.on_exit)
        
        self.toggle_static_fields()

    def on_exit(self):
        """Properly exit the application"""
        if not npyscreen.notify_yes_no("Are you sure you want to exit?", title="Confirm Exit", editw=1):
            logging.info("User cancelled exit.")
            return
        
        logging.info("User confirmed exit via GUI.")
        self.parentApp.switchForm(None)
        self.editing = False
        self.parentApp.switchFormNow()

    def toggle_static_fields(self):
        is_static = not self.chk_dhcp.value
        self.field_ip.hidden = not is_static
        self.field_gw.hidden = not is_static
        self.field_dns.hidden = not is_static
        self.field_ip.editable = is_static
        self.field_gw.editable = is_static
        self.field_dns.editable = is_static
        self.display()

    def get_default_interface(self):
        try:
            cmd = "ip route | grep default | sed -e 's/^.*dev.//' -e 's/.proto.*//'"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            if not result: raise ValueError("Empty result")
            logging.info(f"Network interface detected: {result}")
            return result
        except Exception as e:
            logging.warning(f"Interface detection failed: {e}. Defaulting to eth0.")
            return "eth0"

    def validate_ip(self, ip_input):
        pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$")
        return bool(pattern.match(ip_input))

    def run_cmd(self, command, shell=True):
        logging.info(f"CMD_EXEC: {command}")
        try:
            subprocess.run(command, shell=shell, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"CMD_FAIL: {command} | RC={e.returncode}")
            return False

    def wait_for_network(self, timeout=20):
        logging.info("Waiting for network connectivity...")
        for i in range(timeout):
            if subprocess.run(
                "getent hosts github.com",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ).returncode == 0:
                logging.info("Network & DNS ready.")
                return True
            time.sleep(1)
        logging.error("Network not ready after timeout.")
        return False

    def on_start(self):
        # Validate MOTD install/uninstall conflict
        if self.chk_motd.value and self.chk_motd_uninstall.value:
            npyscreen.notify_confirm("Cannot install and uninstall MOTD at the same time.", title="Validation Error")
            logging.warning("Validation failed: MOTD install and uninstall both selected.")
            return

        if not self.chk_dhcp.value:
            if not all([self.field_ip.value, self.field_gw.value, self.field_dns.value]):
                npyscreen.notify_confirm("Static IP requires: IP, Gateway, DNS.", title="Validation Error")
                logging.warning("Validation failed: Missing static IP fields.")
                return
            if not self.validate_ip(self.field_ip.value):
                npyscreen.notify_confirm("Invalid IP format.", title="Validation Error")
                logging.warning(f"Validation failed: Invalid IP '{self.field_ip.value}'")
                return

        if not npyscreen.notify_yes_no("Apply configuration changes?", title="Confirm", editw=1):
            logging.info("User cancelled operation at confirmation.")
            return

        logging.info("--- STARTING BATCH OPERATIONS ---")
        npyscreen.notify("Executing tasks... Please wait.", title="Working")
        
        self.exec_cleanup()
        self.exec_network()

        # Wait for network if we need MOTD operations
        if self.chk_motd.value or self.chk_motd_uninstall.value:
            if not self.wait_for_network():
                npyscreen.notify_confirm(
                    "Network not ready yet.\nSkipping MOTD operations.",
                    title="Warning"
                )
            else:
                if self.chk_motd_uninstall.value:
                    self.exec_motd_uninstall()
                elif self.chk_motd.value:
                    self.exec_motd()

        self.exec_system()

        logging.info("--- BATCH OPERATIONS COMPLETED ---")
        npyscreen.notify_confirm("Configuration applied successfully.\nA reboot is recommended.", title="Success")
        self.on_exit()

    # --- LOGICA ---

    def exec_motd(self):
        """Install or update MOTD"""
        if not self.chk_motd.value:
            return

        # Check if git is available
        if not shutil.which("git"):
            logging.info("Git not found. Installing...")
            self.run_cmd("apt-get update && apt-get install -y git ca-certificates")

        logging.info("--- STARTING MOTD INSTALLATION ---")
        
        # Create parent directory
        parent_dir = os.path.dirname(MOTD_TARGET_DIR)
        
        if not os.path.exists(parent_dir):
            logging.info(f"Creating directory: {parent_dir}")
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except OSError as e:
                logging.error(f"CRITICAL: Could not create {parent_dir}: {e}")
                return
        
        try:
            os.chmod(parent_dir, 0o755)
            shutil.chown(parent_dir, user="root", group="root")
        except Exception as e:
            logging.warning(f"Could not enforce permissions on {parent_dir}: {e}")

        # Check target directory
        if os.path.exists(MOTD_TARGET_DIR):
            if os.path.isdir(os.path.join(MOTD_TARGET_DIR, ".git")):
                logging.info("MOTD found. Updating...")
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET_DIR)
                if not self.run_cmd("git pull"):
                    logging.warning("Git pull failed. Re-cloning entire repo...")
                    os.chdir(cwd)
                    shutil.rmtree(MOTD_TARGET_DIR)
                    self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}")
                else:
                    os.chdir(cwd)
            else:
                logging.warning(f"Directory {MOTD_TARGET_DIR} is invalid. Wiping and re-cloning...")
                shutil.rmtree(MOTD_TARGET_DIR)
                self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}")
        else:
            logging.info(f"Cloning {MOTD_REPO}...")
            if not self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}"):
                logging.error("Failed to clone MOTD repo. Check URL and Internet!")
                return

        # Run Install Script
        if os.path.exists(MOTD_SCRIPT_PATH):
            logging.info(f"Running MOTD installer: {MOTD_SCRIPT_PATH}")
            try:
                os.chmod(MOTD_SCRIPT_PATH, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET_DIR)
                self.run_cmd("./install.sh")
                os.chdir(cwd)
            except Exception as e:
                logging.error(f"Error executing install.sh: {e}")
        else:
            logging.error(f"install.sh not found at {MOTD_SCRIPT_PATH}")

    def exec_motd_uninstall(self):
        """Uninstall MOTD"""
        if not self.chk_motd_uninstall.value:
            return

        logging.info("--- STARTING MOTD UNINSTALLATION ---")
        
        if not os.path.exists(MOTD_TARGET_DIR):
            logging.warning("MOTD directory not found. Nothing to uninstall.")
            return

        # Run uninstall script if it exists
        if os.path.exists(MOTD_UNINSTALL_PATH):
            logging.info(f"Running MOTD uninstaller: {MOTD_UNINSTALL_PATH}")
            try:
                os.chmod(MOTD_UNINSTALL_PATH, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET_DIR)
                self.run_cmd("./uninstall.sh")
                os.chdir(cwd)
            except Exception as e:
                logging.error(f"Error executing uninstall.sh: {e}")
        else:
            logging.warning(f"uninstall.sh not found at {MOTD_UNINSTALL_PATH}")

        # Remove MOTD directory
        logging.info(f"Removing MOTD directory: {MOTD_TARGET_DIR}")
        try:
            shutil.rmtree(MOTD_TARGET_DIR)
            logging.info("MOTD directory removed successfully")
        except Exception as e:
            logging.error(f"Failed to remove MOTD directory: {e}")

        # Clean up sudoers entries if user exists
        if self.field_user.value:
            user = self.field_user.value
            sudoers_file = f"/etc/sudoers.d/{user}"
            if os.path.exists(sudoers_file):
                try:
                    os.remove(sudoers_file)
                    logging.info(f"Removed sudoers file: {sudoers_file}")
                except Exception as e:
                    logging.error(f"Failed to remove sudoers file: {e}")

    def exec_cleanup(self):
        if self.chk_history.value:
            self.run_cmd("history -c && history -w")
            p = os.path.expanduser("~/.bash_history")
            if os.path.exists(p):
                try: 
                    os.remove(p)
                    logging.info(f"Deleted {p}")
                except OSError as e: logging.error(f"Failed to delete {p}: {e}")

        if self.chk_logs.value:
            logging.info("Truncating log files in /var/log")
            for log_file in Path("/var/log").rglob("*.log"):
                try: log_file.write_text("")
                except PermissionError: logging.warning(f"Permission denied: {log_file}")
            self.run_cmd("find /var/log -type f -name '*.[0-9]*' -delete")

        if self.chk_apt.value:
            self.run_cmd("apt-get clean && apt-get autoremove -y")

        if self.chk_update.value:
            logging.info("Running APT update and upgrade")
            self.run_cmd("apt-get update")
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")

        if self.chk_ssh.value:
            logging.info("Regenerating SSH keys")
            self.run_cmd("rm -f /etc/ssh/ssh_host_*")
            self.run_cmd("dpkg-reconfigure -f noninteractive openssh-server")

        if self.chk_machineid.value:
            logging.info("Resetting machine-id")
            self.run_cmd("truncate -s 0 /etc/machine-id")
            dbus_id = "/var/lib/dbus/machine-id"
            if os.path.exists(dbus_id):
                try: os.remove(dbus_id)
                except OSError: pass
            self.run_cmd("ln -sf /etc/machine-id /var/lib/dbus/machine-id")

        if self.chk_cloudinit.value:
            logging.info("Cleaning cloud-init for VM template preparation")
            self.run_cmd("cloud-init clean --logs --seed")
            self.run_cmd("rm -rf /var/lib/cloud/")
            self.run_cmd("rm -rf /etc/cloud/cloud.cfg.d/99-installer.cfg")
            self.run_cmd("rm -rf /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg")

    def exec_network(self):
        logging.info("Configuring Netplan")
        netplan_file = "/etc/netplan/99-postready.yaml"
        
        if self.chk_dhcp.value:
            content = f"network:\n  version: 2\n  ethernets:\n    {self.detected_iface}:\n      dhcp4: true\n"
            logging.info(f"Mode: DHCP on {self.detected_iface}")
        else:
            ip = self.field_ip.value if "/" in self.field_ip.value else f"{self.field_ip.value}/24"
            content = (
                f"network:\n  version: 2\n  ethernets:\n    {self.detected_iface}:\n"
                f"      dhcp4: false\n      addresses: [{ip}]\n"
                f"      routes:\n        - to: default\n          via: {self.field_gw.value}\n"
                f"      nameservers:\n        addresses: [{self.field_dns.value}]\n"
            )
            logging.info(f"Mode: Static IP {ip} on {self.detected_iface}")

        try:
            backup_dir = Path("/etc/netplan/backup")
            backup_dir.mkdir(exist_ok=True)
            for f in Path("/etc/netplan").glob("*.yaml"):
                if f.name != "99-postready.yaml":
                    shutil.move(str(f), str(backup_dir / f.name))
                    logging.info(f"Backed up {f.name}")

            Path(netplan_file).write_text(content)
            os.chmod(netplan_file, 0o600)
            
            if self.run_cmd("netplan apply"):
                logging.info("Netplan applied successfully")
            else:
                logging.error("Netplan apply failed")
        except Exception as e:
            logging.error(f"Network configuration exception: {e}")

    def exec_system(self):
        if self.field_hostname.value:
            hname = self.field_hostname.value
            logging.info(f"Setting hostname: {hname}")
            self.run_cmd(f"hostnamectl set-hostname {hname}")
            self.run_cmd(f"sed -i 's/127.0.1.1.*/127.0.1.1\t{hname}/' /etc/hosts")

        if self.field_timezone.value:
            tz = self.field_timezone.value
            logging.info(f"Setting timezone: {tz}")
            self.run_cmd(f"timedatectl set-timezone {tz}")

        if self.field_locale.value:
            locale = self.field_locale.value
            logging.info(f"Setting locale: {locale}")
            self.run_cmd(f"locale-gen {locale}")
            self.run_cmd(f"update-locale LANG={locale}")

        if self.field_user.value:
            user = self.field_user.value
            try:
                subprocess.run(f"id -u {user}", shell=True, check=True, stdout=subprocess.DEVNULL)
                logging.info(f"User {user} already exists.")
            except subprocess.CalledProcessError:
                logging.info(f"Creating user: {user}")
                self.run_cmd(f"useradd -m -s /bin/bash {user}")
                self.run_cmd(f"usermod -aG sudo {user}")

            # Only create sudoers file if MOTD is installed, not uninstalled
            if self.chk_motd.value and not self.chk_motd_uninstall.value:
                sudoers_file = f"/etc/sudoers.d/{user}"
                sudo_rule = f"{user} ALL=(root) NOPASSWD: {MOTD_SCRIPT_PATH}\n"
                
                logging.info(f"Checking sudoers permissions for: {user}")
                try:
                    needs_update = True
                    if os.path.exists(sudoers_file):
                        with open(sudoers_file, 'r') as f:
                            if f.read() == sudo_rule:
                                needs_update = False
                    
                    if needs_update:
                        with open(sudoers_file, "w") as f:
                            f.write(sudo_rule)
                        os.chmod(sudoers_file, 0o440)
                        logging.info(f"Sudoers file created/updated: {sudoers_file}")
                except Exception as e:
                    logging.error(f"Failed to configure sudoers: {e}")

class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", PostReadyForm)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Root privileges required. Run with sudo.")
        sys.exit(1)

    logging.info("=== PostReady Application Started ===")
    try:
        PostReadyApp().run()
        logging.info("=== PostReady Application Ended Normally ===")
        
        print("\n" + " PostReady ".center(50, "="))
        # Gebruik f-string voor uitlijning met harde randen
        print(f"= {'Goodbye, see you next time!':<47} =")
        print("="*50 + "\n")
    except KeyboardInterrupt:
        logging.warning("User interrupted process (SIGINT/Ctrl+C)")
        print("\n[WARNING] Process terminated by user.")
        try: sys.exit(0)
        except: os._exit(0)
    except Exception as e:
        logging.critical(f"FATAL EXCEPTION: {e}", exc_info=True)
        print(f"\n[ERROR] Fatal crash. See {LOG_FILE} for details.")
        sys.exit(1)