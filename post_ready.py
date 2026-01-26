#!/usr/bin/env python3
#
# PostReady v2.0 - Advanced System Preparation Tool
# Date: 2026-01-26
# Refactored by: Gemini (Original by Julian Loontjens)
#

import npyscreen
import subprocess
import re
import os
import logging
import shutil
from pathlib import Path
from datetime import datetime

# Instellen van logging
LOG_FILE = "/var/log/postready.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PostReadyForm(npyscreen.FormBaseNew):
    def create(self):
        # --- Centered Header ---
        title = "PostReady v2.0 - System Preparation"
        center_x = int((self.columns - len(title)) / 2)
        
        self.add(npyscreen.FixedText, value=title, editable=False, rely=0, relx=center_x, color="STANDOUT")
        self.add(npyscreen.FixedText, value=f"Logfile: {LOG_FILE}", editable=False, rely=1, relx=2, color="WARNING")

        row = 3

        # --- SYSTEM CLEANUP (Sysprep specific) ---
        self.add(npyscreen.FixedText, value="[ System Cleanup & Sysprep ]", rely=row, relx=2, color="LABEL")
        row += 1
        self.chk_history = self.add(npyscreen.Checkbox, name="Clear Bash History", value=True, rely=row, relx=4)
        row += 1
        self.chk_logs = self.add(npyscreen.Checkbox, name="Truncate Log Files", value=True, rely=row, relx=4)
        row += 1
        self.chk_apt = self.add(npyscreen.Checkbox, name="Clean APT Cache & Autoremove", value=True, rely=row, relx=4)
        row += 1
        self.chk_ssh = self.add(npyscreen.Checkbox, name="Regen SSH Host Keys (Clone safe)", value=False, rely=row, relx=4)
        row += 1
        self.chk_machineid = self.add(npyscreen.Checkbox, name="Reset Machine-ID (Clone safe)", value=False, rely=row, relx=4)
        row += 2

        # --- NETWORK CONFIGURATION ---
        self.add(npyscreen.FixedText, value="[ Network Configuration ]", rely=row, relx=2, color="LABEL")
        row += 1
        # Detect interface
        self.detected_iface = self.get_default_interface()
        self.lbl_iface = self.add(npyscreen.FixedText, value=f"Detected Interface: {self.detected_iface}", rely=row, relx=4, color="GREEN")
        row += 1
        
        # DHCP Checkbox met event listener
        self.chk_dhcp = self.add(npyscreen.Checkbox, name="Use DHCP", value=True, rely=row, relx=4)
        self.chk_dhcp.when_value_edited = self.toggle_static_fields
        row += 1
        
        # Static IP Fields (Hidden by default if DHCP is True)
        self.field_ip = self.add(npyscreen.TitleText, name="Static IP/CIDR:", rely=row, relx=4, hidden=True, begin_entry_at=18)
        self.field_gw = self.add(npyscreen.TitleText, name="Gateway:", rely=row+1, relx=4, hidden=True, begin_entry_at=18)
        self.field_dns = self.add(npyscreen.TitleText, name="DNS Server:", rely=row+2, relx=4, hidden=True, begin_entry_at=18)
        row += 4

        # --- SYSTEM SETTINGS ---
        self.add(npyscreen.FixedText, value="[ General Settings ]", rely=row, relx=2, color="LABEL")
        row += 1
        self.field_hostname = self.add(npyscreen.TitleText, name="Set Hostname:", rely=row, relx=4, begin_entry_at=18)
        row += 1
        self.field_user = self.add(npyscreen.TitleText, name="Create User:", rely=row, relx=4, begin_entry_at=18)
        row += 2

        # --- ACTION ---
        self.btn_start = self.add(npyscreen.ButtonPress, name=" >> EXECUTE TASKS << ", rely=row, relx=int(self.columns/2)-10, when_pressed_function=self.on_start)
        
        # Trigger initial visibility check
        self.toggle_static_fields()

    def toggle_static_fields(self):
        """Verbergt of toont statische IP velden op basis van DHCP selectie"""
        is_static = not self.chk_dhcp.value
        self.field_ip.hidden = not is_static
        self.field_gw.hidden = not is_static
        self.field_dns.hidden = not is_static
        self.field_ip.editable = is_static
        self.field_gw.editable = is_static
        self.field_dns.editable = is_static
        self.display()

    def get_default_interface(self):
        """Probeert de primaire netwerkinterface te vinden."""
        try:
            # Een simpele manier om de actieve interface te vinden via de route
            cmd = "ip route | grep default | sed -e 's/^.*dev.//' -e 's/.proto.*//'"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result if result else "eth0"
        except:
            return "eth0" # Fallback

    def validate_ip(self, ip_input):
        # Simpele regex voor IP en optionele CIDR (bijv. 192.168.1.50 of 192.168.1.50/24)
        pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$")
        return bool(pattern.match(ip_input))

    def run_command(self, command, shell=True):
        """Wrapper om commando's uit te voeren met logging"""
        logging.info(f"Executing: {command}")
        try:
            subprocess.run(command, shell=shell, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {command} | Error: {e}")
            return False

    def on_start(self):
        # Validatie
        if not self.chk_dhcp.value:
            if not all([self.field_ip.value, self.field_gw.value, self.field_dns.value]):
                npyscreen.notify_confirm("For Static IP, please fill in IP, Gateway and DNS.", title="Missing Info")
                return
            if not self.validate_ip(self.field_ip.value):
                npyscreen.notify_confirm("Invalid IP format. Use: x.x.x.x or x.x.x.x/24", title="Input Error")
                return

        confirm = npyscreen.notify_yes_no("Are you sure you want to apply these changes?\nSystem configuration will be modified.", title="Confirm", editw=1)
        if not confirm:
            return

        # Start Execution
        npyscreen.notify("Processing... Check /var/log/postready.log for details.", title="Running")
        
        self.execute_cleanup()
        self.execute_network()
        self.execute_system_settings()

        npyscreen.notify_confirm("Tasks completed!\nIt is recommended to reboot the system.", title="Done")
        self.parentApp.setNextForm(None)

    # --- LOGIC MODULES ---

    def execute_cleanup(self):
        logging.info("--- Starting Cleanup ---")
        
        if self.chk_history.value:
            # Geschiedenis wissen in de huidige sessie en bestand
            self.run_command("history -c && history -w")
            if os.path.exists(os.path.expanduser("~/.bash_history")):
                os.remove(os.path.expanduser("~/.bash_history"))

        if self.chk_logs.value:
            # Logs truncaten ipv verwijderen (veiliger voor services)
            for log_file in Path("/var/log").rglob("*.log"):
                try:
                    log_file.write_text("")
                except PermissionError:
                    logging.warning(f"Permission denied clearing log: {log_file}")
            # Verwijder rotated logs (bijv. syslog.1, syslog.2.gz)
            self.run_command("find /var/log -type f -name '*.[0-9]*' -delete")

        if self.chk_apt.value:
            self.run_command("apt-get clean && apt-get autoremove -y")

        if self.chk_ssh.value:
            # Verwijder host keys. Ze worden opnieuw gegenereerd bij reboot (indien package reconfigure)
            # Of we kunnen ze direct regenereren.
            logging.info("Removing SSH Host Keys...")
            self.run_command("rm -f /etc/ssh/ssh_host_*")
            self.run_command("dpkg-reconfigure openssh-server")

        if self.chk_machineid.value:
            # Essentieel voor cloning
            logging.info("Resetting Machine ID...")
            self.run_command("truncate -s 0 /etc/machine-id")
            if os.path.exists("/var/lib/dbus/machine-id"):
                os.remove("/var/lib/dbus/machine-id")
            self.run_command("ln -s /etc/machine-id /var/lib/dbus/machine-id")

    def execute_network(self):
        logging.info("--- Configuring Network ---")
        netplan_path = Path("/etc/netplan/99-postready.yaml")
        
        if self.chk_dhcp.value:
            content = f"""network:
  version: 2
  ethernets:
    {self.detected_iface}:
      dhcp4: true
"""
        else:
            # Zorg dat CIDR notatie klopt
            ip_val = self.field_ip.value
            if "/" not in ip_val:
                ip_val += "/24" # Default als gebruiker het vergeet

            content = f"""network:
  version: 2
  ethernets:
    {self.detected_iface}:
      dhcp4: false
      addresses: [{ip_val}]
      routes:
        - to: default
          via: {self.field_gw.value}
      nameservers:
        addresses: [{self.field_dns.value}]
"""
        
        try:
            netplan_path.write_text(content)
            # Oude configs verwijderen om conflicten te voorkomen? Risicovol, dus we verplaatsen ze naar backup
            backup_dir = Path("/etc/netplan/backup")
            backup_dir.mkdir(exist_ok=True)
            for f in Path("/etc/netplan").glob("*.yaml"):
                if f.name != "99-postready.yaml":
                    shutil.move(str(f), str(backup_dir / f.name))
            
            self.run_command("chmod 600 /etc/netplan/99-postready.yaml")
            self.run_command("netplan apply")
        except Exception as e:
            logging.error(f"Network config failed: {e}")

    def execute_system_settings(self):
        logging.info("--- System Settings ---")

        if self.field_hostname.value:
            new_host = self.field_hostname.value
            logging.info(f"Setting hostname to {new_host}")
            self.run_command(f"hostnamectl set-hostname {new_host}")
            # Update /etc/hosts
            self.run_command(f"sed -i 's/127.0.1.1.*/127.0.1.1\t{new_host}/' /etc/hosts")

        if self.field_user.value:
            user = self.field_user.value
            try:
                # Check of user bestaat
                subprocess.run(f"id -u {user}", shell=True, check=True, stdout=subprocess.DEVNULL)
                logging.info(f"User {user} already exists.")
            except subprocess.CalledProcessError:
                logging.info(f"Creating user {user}")
                # User aanmaken met home dir en bash
                self.run_command(f"useradd -m -s /bin/bash {user}")
                # Optioneel: user aan sudo groep toevoegen
                self.run_command(f"usermod -aG sudo {user}")

class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", PostReadyForm)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Error: Dit script moet als root worden uitgevoerd (sudo).")
        exit(1)

    try:
        PostReadyApp().run()
    except Exception as e:
        logging.critical(f"Applicatie crash: {e}")
        print(f"Er ging iets mis. Bekijk {LOG_FILE} voor details.")