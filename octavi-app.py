"""
Octavi IFR1 Udev Rules Manager
Version: 0.011

This script provides a GUI application for managing udev rules for the Octavi IFR1 device.
Key features:
- List and view existing Octavi udev rules
- Create new udev rules with proper permissions and group settings
- Reload and trigger udev rules
- Monitor hidraw devices and their permissions
- Search for Octavi IFR1 devices and set appropriate permissions
- View kernel messages related to hidraw devices
- Supports sudo operations with password authentication

The application helps users set up and manage their Octavi IFR1 device permissions
on Linux systems using udev rules.
"""

import sys
import os
import subprocess
import glob
import re
import time
from cryptography.fernet import Fernet
from base64 import b64encode
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QSplitter,
                             QListWidget, QInputDialog, QLineEdit, QLabel,
                             QStatusBar, QGridLayout)
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor
from PyQt6.QtCore import Qt, QSize, QTimer, QRect, QPoint

class PasswordCache:
    def __init__(self, timeout_minutes=10):
        self.timeout_minutes = timeout_minutes
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.cached_password = None
        self.cache_time = None
        self.cache_status_changed_callback = None
    
    def set_status_callback(self, callback):
        self.cache_status_changed_callback = callback
    
    def cache_password(self, password):
        self.cached_password = self.cipher_suite.encrypt(password.encode())
        self.cache_time = time.time()
        if self.cache_status_changed_callback:
            self.cache_status_changed_callback(True)
    
    def get_password(self):
        if not self.cached_password or not self.cache_time:
            return None
        
        # Check if cache has expired
        if time.time() - self.cache_time > (self.timeout_minutes * 60):
            self.clear_cache()
            return None
            
        return self.cipher_suite.decrypt(self.cached_password).decode()
    
    def clear_cache(self):
        self.cached_password = None
        self.cache_time = None
        if self.cache_status_changed_callback:
            self.cache_status_changed_callback(False)

class RootStatusIcon(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.active = False
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw circle
        if self.active:
            painter.setBrush(QColor(255, 0, 0))  # Red when active
        else:
            painter.setBrush(QColor(128, 128, 128))  # Gray when inactive
        
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPoint(8, 8), 7, 7)
        
        # Draw exclamation mark
        painter.setPen(QColor(255, 255, 255))
        painter.drawLine(8, 4, 8, 9)
        painter.drawPoint(8, 11)
        
        painter.end()
    
    def set_active(self, active):
        self.active = active
        self.update()

class UdevRulesApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.version = "0.011"  # Incremented version
        self.password_cache = PasswordCache()
        self.password_cache.set_status_callback(self.update_root_status)
        self.initUI()
        self.list_octavi_rules()

    def initUI(self):
        self.setWindowTitle('Octavi IFR1 Manager')
        self.setGeometry(100, 100, 1200, 800)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #dddddd;
                border-radius: 4px;
                padding: 8px 16px;
                min-width: 120px;
                color: #333333;
            }
            QPushButton:hover {
                background-color: #e6e6e6;
                border-color: #adadad;
            }
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #dddddd;
                border-radius: 4px;
                padding: 8px;
            }
            QListWidget {
                background-color: #ffffff;
                border: 1px solid #dddddd;
                border-radius: 4px;
                padding: 4px;
            }
            QStatusBar {
                background-color: #ffffff;
                border-top: 1px solid #dddddd;
            }
        """)

        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Header section with logo and title
        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 20)

        # Add image
        image_label = QLabel()
        image_path = os.path.join(os.path.dirname(__file__), "octavi_ifr1.jpg")
        
        if os.path.exists(image_path):
            pixmap = QPixmap(image_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, 
                                            Qt.TransformationMode.SmoothTransformation)
                image_label.setPixmap(scaled_pixmap)
                image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Add title
        title_label = QLabel("Octavi IFR1 Manager")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #333333;
                margin-left: 20px;
            }
        """)
        
        header_layout.addWidget(image_label)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_widget.setLayout(header_layout)
        main_layout.addWidget(header_widget)

        # Content area
        content_widget = QWidget()
        content_layout = QHBoxLayout()
        content_layout.setSpacing(20)

        # Left panel (buttons and file list)
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)

        # Button grid
        button_grid = QWidget()
        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)

        # Create buttons with modern style and connect them
        buttons = [
            ("List Rules", "folder", False, self.list_octavi_rules),
            ("Reload Rules", "view-refresh", True, self.reload_rules),
            ("Trigger Rules", "system-run", True, self.trigger_rules),
            ("Show Permissions", "dialog-information", False, self.show_hidraw_permissions),
            ("View Logs", "utilities-terminal", True, self.dmesg_hidraw),
            ("Create Rule", "document-new", True, self.create_udev_rule),
            ("Find Device", "edit-find", True, self.run_find_octavi_device),
            ("Check Group", "system-users", True, self.check_plugdev_group)
        ]

        for i, (text, icon, sudo, callback) in enumerate(buttons):
            row = i // 2
            col = i % 2
            btn = self.create_modern_button(icon, text, sudo)
            btn.clicked.connect(callback)  # Connect the button to its callback
            grid_layout.addWidget(btn, row, col)

        button_grid.setLayout(grid_layout)
        left_layout.addWidget(button_grid)

        # File list with title
        list_label = QLabel("Octavi Rules")
        list_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #333333;")
        left_layout.addWidget(list_label)

        self.file_list = QListWidget()
        self.file_list.setStyleSheet("""
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #eeeeee;
            }
            QListWidget::item:selected {
                background-color: #e6e6e6;
                color: #333333;
            }
        """)
        self.file_list.itemClicked.connect(self.display_file_contents)  # Connect item click event
        left_layout.addWidget(self.file_list)
        left_panel.setLayout(left_layout)

        # Right panel (output and instructions)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        
        # Output section
        output_label = QLabel("Output")
        output_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #333333;")
        right_layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        right_layout.addWidget(self.output_text)

        # Instructions section
        instructions_label = QLabel("Instructions")
        instructions_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #333333;")
        right_layout.addWidget(instructions_label)
        
        self.instructions_text = QTextEdit()
        self.instructions_text.setReadOnly(True)
        right_layout.addWidget(self.instructions_text)
        
        right_panel.setLayout(right_layout)

        # Add panels to content layout
        content_layout.addWidget(left_panel, 1)
        content_layout.addWidget(right_panel, 2)
        content_widget.setLayout(content_layout)
        main_layout.addWidget(content_widget)

        # Status bar
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("""
            QStatusBar::item {
                border: none;
            }
        """)
        self.setStatusBar(self.statusBar)
        
        self.root_status = RootStatusIcon()
        self.root_status.setToolTip("Root password not cached")
        self.statusBar.addPermanentWidget(self.root_status)
        
        self.version_label = QLabel(f"Ver:{self.version}")
        self.version_label.setStyleSheet("color: #666666; padding-right: 5px;")
        self.statusBar.addPermanentWidget(self.version_label)

        # Set main widget
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Set initial instructions
        self.set_instructions()

    def create_modern_button(self, icon_name, text, sudo=False):
        """Create a modern-styled button with icon and text"""
        button = QPushButton(text)  # Create button with text
        button.setFixedHeight(40)
        
        # Create layout for button contents
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 0, 5, 0)
        layout.setSpacing(10)
        
        # Add icon
        icon = QIcon.fromTheme(icon_name)
        button.setIcon(icon)
        button.setIconSize(QSize(24, 24))
        
        # Add sudo icon if needed
        if sudo:
            sudo_icon = QIcon.fromTheme("dialog-password")
            # Create combined icon
            combined_pixmap = QPixmap(32, 24)
            combined_pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(combined_pixmap)
            painter.drawPixmap(0, 0, icon.pixmap(24, 24))
            painter.drawPixmap(16, 8, sudo_icon.pixmap(16, 16))
            painter.end()
            button.setIcon(QIcon(combined_pixmap))
        
        return button

    def list_octavi_rules(self):
        self.file_list.clear()
        rules_dir = '/etc/udev/rules.d/'
        try:
            # Check if directory exists
            if not os.path.exists(rules_dir):
                self.output_text.setPlainText(f"Directory {rules_dir} does not exist.")
                return

            # List all files and filter for octavi
            files = [f for f in os.listdir(rules_dir) if 'octavi' in f.lower()]
            
            # Add files to list widget
            for filename in files:
                self.file_list.addItem(filename)
            
            # Update output text
            if len(files) == 0:
                self.output_text.setPlainText("No Octavi rules found.")
            else:
                self.output_text.setPlainText(f"Found {len(files)} Octavi rule(s).")
                
            # Debug output
            self.output_text.append("\nSearched directory: " + rules_dir)
            self.output_text.append("All files in directory: " + str(os.listdir(rules_dir)))
            
        except Exception as e:
            self.output_text.setPlainText(f"Error listing files: {str(e)}\n{type(e).__name__}")

    def display_file_contents(self, item):
        filename = item.text()
        file_path = os.path.join('/etc/udev/rules.d/', filename)
        try:
            with open(file_path, 'r') as file:
                content = file.read()
            self.output_text.setPlainText(content)
        except Exception as e:
            self.output_text.setPlainText(f"Error reading file: {str(e)}")

    def reload_rules(self):
        self.run_sudo_command("udevadm control --reload-rules")

    def trigger_rules(self):
        self.run_sudo_command("udevadm trigger")

    def run_sudo_command(self, command, password=None, callback=None):
        # Try to get cached password first
        cached_password = self.password_cache.get_password()
        
        if cached_password:
            password = cached_password
        elif password is None:
            password, ok = QInputDialog.getText(self, "Sudo Password", 
                                              "Enter sudo password:", 
                                              QLineEdit.EchoMode.Password)
            if not ok:
                self.output_text.setPlainText("Operation cancelled.")
                return
            # Cache the new password
            self.password_cache.cache_password(password)

        full_command = f"echo {password} | sudo -S {command}"
        try:
            result = subprocess.run(full_command, shell=True, check=True, 
                                  capture_output=True, text=True)
            output = result.stdout if result.stdout else "Command executed successfully."
            if callback:
                callback(output)
            else:
                self.output_text.setPlainText(output)
        except subprocess.CalledProcessError as e:
            output = f"Error executing command: {e.stderr}"
            self.output_text.setPlainText(output)
            # If the error is due to wrong password, clear the cache
            if "incorrect password" in e.stderr.lower():
                self.password_cache.clear_cache()

    def show_hidraw_permissions(self):
        try:
            hidraw_devices = glob.glob('/dev/hidraw*')
            if not hidraw_devices:
                self.output_text.setPlainText("No hidraw devices found.")
                return

            output = "Hidraw device permissions:\n\n"
            for device in hidraw_devices:
                ls_output = subprocess.check_output(['ls', '-l', device], universal_newlines=True).strip()
                output += f"{ls_output}\n"

            self.output_text.setPlainText(output)
        except Exception as e:
            self.output_text.setPlainText(f"Error retrieving hidraw permissions: {str(e)}")

    def dmesg_hidraw(self):
        def highlight_octavi_ifr1(output):
            lines = output.split('\n')
            highlighted_lines = []
            for line in lines:
                if 'octavi ifr1' in line.lower():
                    highlighted_lines.append(f"<b>{line}</b>")
                else:
                    highlighted_lines.append(line)
            return '<br>'.join(highlighted_lines)

        def process_output(output):
            highlighted_output = highlight_octavi_ifr1(output)
            self.output_text.setHtml(highlighted_output)

        self.run_sudo_command("dmesg | grep -i 'hidraw\\|octavi'", callback=process_output)

    def create_udev_rule(self):
        command = 'echo "SUBSYSTEM==\\"usb\\", ATTR{idVendor}==\\"04d8\\", ATTR{idProduct}==\\"e6d6\\", MODE=\\"0666\\", GROUP=\\"plugdev\\"" > /etc/udev/rules.d/99-octavi.rules'
        self.run_sudo_command(command)
        self.output_text.setPlainText("Udev rule created. Please reload rules and trigger udev for changes to take effect.")

    def find_octavi_device(self, password):
        # Cache the password if it's not already cached
        if not self.password_cache.get_password():
            self.password_cache.cache_password(password)
            
        VENDOR_ID = "04D8"
        PRODUCT_ID = "E6D6"
        
        found_devices = []
        
        self.output_text.setPlainText("Searching for Octavi IFR1 devices...")
        QApplication.processEvents()
        
        hidraw_devices = glob.glob('/dev/hidraw*')
        
        for hidraw in hidraw_devices:
            try:
                device_info = subprocess.check_output(['sudo', '-S', 'udevadm', 'info', '--query=all', '--name=' + hidraw], 
                                                  input=password if isinstance(password, bytes) else password.encode(),
                                                  stderr=subprocess.PIPE)
                
                # Decode the bytes to a string
                device_info_str = device_info.decode('utf-8')
                
                devpath_match = re.search(r'DEVPATH=.*0003:([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})', device_info_str)
                
                if devpath_match:
                    current_vendor_id, current_product_id = devpath_match.groups()
                    
                    if current_vendor_id.upper() == VENDOR_ID and current_product_id.upper() == PRODUCT_ID:
                        found_devices.append(hidraw)
            except subprocess.CalledProcessError:
                continue

        if found_devices:
            result = "Found Octavi IFR1 device(s):\n"
            for device in found_devices:
                result += f"{device}\n"
                try:
                    subprocess.run(['sudo', '-S', 'chmod', '0666', device], input=password.encode(), check=True)
                    result += f"Applied chmod 0666 to {device}\n"
                except subprocess.CalledProcessError:
                    result += f"Failed to apply chmod 0666 to {device}\n"
        else:
            result = "No Octavi IFR1 devices found."

        self.output_text.setPlainText(result)
        QApplication.processEvents()

    def run_find_octavi_device(self):
        # Try to get cached password first
        cached_password = self.password_cache.get_password()
        
        if cached_password:
            password = cached_password
        else:
            password, ok = QInputDialog.getText(self, "Sudo Password", "Enter sudo password:", QLineEdit.EchoMode.Password)
            if not ok:
                self.output_text.setPlainText("Operation cancelled.")
                return
            # Cache the new password
            self.password_cache.cache_password(password)
        
        self.output_text.clear()
        self.output_text.setPlainText("Preparing to search for Octavi IFR1 devices...")
        QTimer.singleShot(100, lambda: self.find_octavi_device(password))

    def check_plugdev_group(self):
        current_user = os.getenv('USER')
        
        try:
            # Check if plugdev group exists
            result = subprocess.run(['getent', 'group', 'plugdev'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                # Group doesn't exist, create it
                self.run_sudo_command('groupadd plugdev')
                self.output_text.setPlainText("Created plugdev group.\n")
            
            # Check if user is in the group
            groups_output = subprocess.check_output(['groups', current_user], 
                                                 universal_newlines=True)
            
            if 'plugdev' not in groups_output:
                # User not in group, add them
                self.run_sudo_command(f'usermod -a -G plugdev {current_user}')
                self.output_text.setPlainText(
                    f"Added user {current_user} to plugdev group.\n"
                    "Please log out and log back in for changes to take effect."
                )
            else:
                self.output_text.setPlainText(
                    f"User {current_user} is already in the plugdev group."
                )
                
        except Exception as e:
            self.output_text.setPlainText(f"Error checking/modifying group: {str(e)}")

    def set_instructions(self):
        instructions = """
        Instructions:

        1. List Octavi Rules: Display all Octavi-related udev rules.
        2. Reload Rules: Reload udev rules (requires sudo).
        3. Trigger Rules: Trigger udev rules (requires sudo).
        4. Show Hidraw Permissions: Display permissions for hidraw devices.
        5. Dmesg Hidraw: Show hidraw-related kernel messages (requires sudo).
        6. Create Udev Rule: Create a new udev rule for Octavi (requires sudo).
        7. Find Octavi Device: Search for Octavi devices and set permissions (requires sudo).
        8. Check Plugdev Group: Check and add current user to plugdev group (requires sudo).

        Note: Actions marked with (requires sudo) will prompt for your password.
        """
        self.instructions_text.setPlainText(instructions)

    def closeEvent(self, event):
        # Clear password cache when application closes
        self.password_cache.clear_cache()
        super().closeEvent(event)

    def update_root_status(self, active):
        """Update the root status icon when password cache status changes"""
        self.root_status.set_active(active)
        if active:
            self.root_status.setToolTip("Root password cached")
        else:
            self.root_status.setToolTip("Root password not cached")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = UdevRulesApp()
    ex.show()
    sys.exit(app.exec())