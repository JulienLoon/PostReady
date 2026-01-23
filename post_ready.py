#!/usr/bin/env python3
import npyscreen
import subprocess
import re
from pathlib import Path

class PostReadyForm(npyscreen.FormMultiPage):
    def create(self):
        self.add(npyscreen.TitleFixedText, name="POST-READY CONFIGURATOR", value="Use arrow keys and space to select options")

        # --- Pre-template ---
        self.add(npyscreen.FixedText, value="Pre-template Cleanup", editable=False)
        self.cleanup_history = self.add(npyscreen.Checkbox, name="Clear bash history")
        self.cleanup_logs = self.add(npyscreen.Checkbox, name="Clear /var/log files")
        self.cleanup_cache = self.add(npyscreen.Checkbox, name="Clear caches")

        # --- Initial Setup ---
        self.add(npyscreen.FixedText, value="Initial Setup", editable=False)
        self.use_dhcp = self.add(npyscreen.Checkbox, name="Use DHCP")
        self.static_ip = self.add(npyscreen.TitleText, name="Static IP:")
        self.gateway = self.add(npyscreen.TitleText, name="Gateway:")
        self.dns = self.add(npyscreen.TitleText, name="DNS:")

        # --- Losse Componenten ---
        self.add(npyscreen.FixedText, value="Loose Components", editable=False)
        self.install_motd = self.add(npyscreen.Checkbox, name="Install MOTD")
        self.reset_motd = self.add(npyscreen.Checkbox, name="Reset MOTD")
        self.create_user = self.add(npyscreen.TitleText, name="Create user:")

        # --- Start button ---
        self.start = self.add(npyscreen.ButtonPress, name="START", when_pressed_function=self.on_start)

    def on_start(self):
        # --- Validation ---
        if not self.use_dhcp.value:
            if not all([self.static_ip.value, self.gateway.value, self.dns.value]):
                npyscreen.notify_confirm("Please fill all static IP fields or select DHCP.", title="Validation Error")
                return
            if not self.validate_ip(self.static_ip.value):
                npyscreen.notify_confirm("Invalid IP address format.", title="Validation Error")
                return
        # --- Execute selections ---
        self.execute_cleanup()
        self.execute_network()
        self.execute_components()
        npyscreen.notify_confirm("All selected tasks completed.", title="Done")
        self.parentApp.setNextForm(None)

    def validate_ip(self, ip):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return pattern.match(ip) is not None

    def execute_cleanup(self):
        if self.cleanup_history.value:
            subprocess.run("history -c && history -w", shell=True)
        if self.cleanup_logs.value:
            for log_file in Path("/var/log").glob("*"):
                if log_file.is_file():
                    try:
                        log_file.write_text("")
                    except PermissionError:
                        pass
        if self.cleanup_cache.value:
            subprocess.run("rm -rf /var/cache/*", shell=True)

    def execute_network(self):
        if self.use_dhcp.value:
            content = """
network:
    ethernets:
        ens18:
            dhcp4: true
    version: 2
"""
        else:
            content = f"""
network:
    ethernets:
        ens18:
            dhcp4: false
            addresses: [{self.static_ip.value}/24]
            routes:
              - to: default
                via: {self.gateway.value}
            nameservers:
                addresses: [{self.dns.value}]
    version: 2
"""
        netplan_file = Path("/etc/netplan/50-cloud-init.yaml")
        netplan_file.write_text(content)
        subprocess.run("netplan apply", shell=True)

    def execute_components(self):
        if self.install_motd.value:
            subprocess.run("cp -r motd/* /etc/update-motd.d/ && chmod 755 /etc/update-motd.d/*", shell=True)
        if self.reset_motd.value:
            for f in Path("/etc/update-motd.d").glob("*"):
                f.unlink()
        if self.create_user.value:
            try:
                subprocess.run(f"id -u {self.create_user.value}", shell=True, check=True)
            except subprocess.CalledProcessError:
                subprocess.run(f"useradd -m -s /bin/bash {self.create_user.value}", shell=True)

class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", PostReadyForm)

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("✗ Must be run as root!")
        exit(1)
    PostReadyApp().run()
