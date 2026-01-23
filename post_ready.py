# 
# PostReady - A tool for post-image preparation
# Date: 23-01-2026
# By Julian Loontjens
#

#!/usr/bin/env python3
import npyscreen
import subprocess
import re
from pathlib import Path

class PostReadyForm(npyscreen.FormBaseNew):
    def create(self):
        # --- Centered top title ---
        title = "PostReady by Julian Loontjens"
        center_x = int((self.columns - len(title)) / 2)

        self.add(
            npyscreen.FixedText,
            value=title,
            editable=False,
            rely=0,
            relx=center_x,
            color="STANDOUT"
        )

        # --- Subtitle / hint ---
        self.add(
            npyscreen.FixedText,
            value="Use arrow keys and space to select options",
            editable=False,
            rely=3,
            relx=2
        )

        row = 5

        # --- Pre-image Cleanup ---
        self.add(npyscreen.FixedText, value="Pre-image Cleanup", rely=row, relx=2, editable=False, color="LABEL")
        row += 1
        self.cleanup_history = self.add(npyscreen.Checkbox, name="Clear bash history", rely=row, relx=4)
        row += 1
        self.cleanup_logs = self.add(npyscreen.Checkbox, name="Clear /var/log files", rely=row, relx=4)
        row += 1
        self.cleanup_cache = self.add(npyscreen.Checkbox, name="Clear caches", rely=row, relx=4)
        row += 2

        # --- Initial Setup ---
        self.add(npyscreen.FixedText, value="Initial Setup", rely=row, relx=2, editable=False, color="LABEL")
        row += 1
        self.use_dhcp = self.add(npyscreen.Checkbox, name="Use DHCP", rely=row, relx=4)
        row += 1
        self.static_ip = self.add(npyscreen.TitleText, name="Static IP:", rely=row, relx=4, begin_entry_at=16)
        row += 1
        self.gateway = self.add(npyscreen.TitleText, name="Gateway:", rely=row, relx=4, begin_entry_at=16)
        row += 1
        self.dns = self.add(npyscreen.TitleText, name="DNS:", rely=row, relx=4, begin_entry_at=16)
        row += 2

        # --- Loose Components ---
        self.add(npyscreen.FixedText, value="Loose Components", rely=row, relx=2, editable=False, color="LABEL")
        row += 1
        self.install_motd = self.add(npyscreen.Checkbox, name="Install MOTD", rely=row, relx=4)
        row += 1
        self.reset_motd = self.add(npyscreen.Checkbox, name="Reset MOTD", rely=row, relx=4)
        row += 1
        self.create_user = self.add(npyscreen.TitleText, name="Create user:", rely=row, relx=4, begin_entry_at=16)
        row += 2

        # --- Start button ---
        self.start = self.add(
            npyscreen.ButtonPress,
            name="START",
            rely=row,
            relx=2,
            when_pressed_function=self.on_start
        )

    def on_start(self):
        if not self.use_dhcp.value:
            if not all([self.static_ip.value, self.gateway.value, self.dns.value]):
                npyscreen.notify_confirm(
                    "Please fill all static IP fields or select DHCP.",
                    title="Validation Error"
                )
                return

            if not self.validate_ip(self.static_ip.value):
                npyscreen.notify_confirm(
                    "Invalid IP address format.",
                    title="Validation Error"
                )
                return

        self.execute_cleanup()
        self.execute_network()
        self.execute_components()

        npyscreen.notify_confirm(
            "All selected tasks completed successfully.",
            title="Done"
        )
        self.parentApp.setNextForm(None)

    def validate_ip(self, ip):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return bool(pattern.match(ip))

    # --- Execution Methods ---
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
            content = """\
network:
  ethernets:
    ens18:
      dhcp4: true
  version: 2
"""
        else:
            content = f"""\
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
            subprocess.run(
                "cp -r motd/* /etc/update-motd.d/ && chmod 755 /etc/update-motd.d/*",
                shell=True
            )

        if self.reset_motd.value:
            for f in Path("/etc/update-motd.d").glob("*"):
                f.unlink(missing_ok=True)

        if self.create_user.value:
            try:
                subprocess.run(
                    f"id -u {self.create_user.value}",
                    shell=True,
                    check=True
                )
            except subprocess.CalledProcessError:
                subprocess.run(
                    f"useradd -m -s /bin/bash {self.create_user.value}",
                    shell=True
                )

class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", PostReadyForm)

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("✗ Must be run as root!")
        exit(1)

    PostReadyApp().run()
