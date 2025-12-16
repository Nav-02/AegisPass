import sys
import json
import os
import shutil
import time
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QStackedWidget, 
                             QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QDialog, QFormLayout, QCheckBox)
from PyQt6.QtCore import Qt
from fpdf import FPDF
from aegis import Aegis

class AegisPassApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AegisPass")
        self.resize(900, 600)
        self.aegis = Aegis()
        self.current_file_path = None
        self.vault_data = []    
        self.dek = None         
        self.file_structure = None 
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)
        self.init_welcome_screen()
        self.init_setup_screen()
        self.init_unlock_screen()
        self.init_vault_screen()

    def init_welcome_screen(self):
        page = QWidget()
        layout = QVBoxLayout()
        title = QLabel("AegisPass")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 32px; font-weight: bold; color: #2c3e50;")
        btn_create = QPushButton("Create New Vault")
        btn_create.clicked.connect(lambda: self.central_widget.setCurrentWidget(self.setup_page))
        btn_open = QPushButton("Open Existing Vault")
        btn_open.clicked.connect(self.open_vault_file_dialog)
        layout.addStretch()
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(btn_create)
        layout.addWidget(btn_open)
        layout.addStretch()
        page.setLayout(layout)
        self.central_widget.addWidget(page)

    def init_setup_screen(self):
        self.setup_page = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("<h2>Create Your Fortress</h2>"))
        self.setup_pass = QLineEdit()
        self.setup_pass.setPlaceholderText("Master Password")
        self.setup_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.q1_ans = QLineEdit()
        self.q1_ans.setPlaceholderText("Question 1")
        self.q2_ans = QLineEdit()
        self.q2_ans.setPlaceholderText("Question 2")
        btn_generate = QPushButton("Generate Vault & Recovery Kit")
        btn_generate.clicked.connect(self.handle_create_vault)
        btn_back = QPushButton("Back")
        btn_back.clicked.connect(lambda: self.central_widget.setCurrentIndex(0))
        layout.addWidget(self.setup_pass)
        layout.addWidget(self.q1_ans)
        layout.addWidget(self.q2_ans)
        layout.addWidget(btn_generate)
        layout.addWidget(btn_back)
        layout.addStretch()
        self.setup_page.setLayout(layout)
        self.central_widget.addWidget(self.setup_page)

    def init_unlock_screen(self):
        self.unlock_page = QWidget()
        layout = QVBoxLayout()
        self.lbl_file_name = QLabel("No file selected")
        self.unlock_pass = QLineEdit()
        self.unlock_pass.setPlaceholderText("Master Password")
        self.unlock_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.unlock_q1 = QLineEdit()
        self.unlock_q1.setPlaceholderText("Answer to Q1")
        self.unlock_q2 = QLineEdit()
        self.unlock_q2.setPlaceholderText("Answer to Q2")
        self.chk_recovery = QPushButton("I lost my password - Use Recovery Key")
        self.chk_recovery.setCheckable(True)
        self.chk_recovery.toggled.connect(self.toggle_recovery_mode)
        self.recovery_input = QLineEdit()
        self.recovery_input.setPlaceholderText("Paste your long Recovery Key here")
        self.recovery_input.setVisible(False)
        btn_unlock = QPushButton("Unlock Vault")
        btn_unlock.clicked.connect(self.handle_unlock)
        layout.addWidget(self.lbl_file_name)
        layout.addWidget(self.unlock_pass)
        layout.addWidget(self.unlock_q1)
        layout.addWidget(self.unlock_q2)
        layout.addWidget(self.chk_recovery)
        layout.addWidget(self.recovery_input)
        layout.addWidget(btn_unlock)
        layout.addStretch()
        self.unlock_page.setLayout(layout)
        self.central_widget.addWidget(self.unlock_page)

    def init_vault_screen(self):
        self.vault_page = QWidget()
        layout = QVBoxLayout()
        self.lbl_vault_status = QLabel("Vault Unlocked")
        toolbar = QHBoxLayout()
        btn_add = QPushButton(" + Add Entry")
        btn_add.clicked.connect(self.show_add_dialog)
        self.chk_show_pass = QCheckBox("Show Passwords")
        self.chk_show_pass.stateChanged.connect(self.refresh_table)
        btn_save = QPushButton("Save Changes")
        btn_save.setStyleSheet("background-color: #27ae60; color: white;")
        btn_save.clicked.connect(self.save_vault_changes)
        btn_lock = QPushButton("Lock Vault")
        btn_lock.clicked.connect(self.lock_vault)
        toolbar.addWidget(btn_add)
        toolbar.addStretch()
        toolbar.addWidget(self.chk_show_pass)
        toolbar.addWidget(btn_save)
        toolbar.addWidget(btn_lock)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.lbl_vault_status)
        layout.addLayout(toolbar)
        layout.addWidget(self.table)
        self.vault_page.setLayout(layout)
        self.central_widget.addWidget(self.vault_page)

    def toggle_recovery_mode(self, checked):
        self.unlock_pass.setVisible(not checked)
        self.unlock_q1.setVisible(not checked)
        self.unlock_q2.setVisible(not checked)
        self.recovery_input.setVisible(checked)

    def open_vault_file_dialog(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open Vault', '.', "JSON Files (*.json)")
        if fname:
            self.current_file_path = fname
            self.lbl_file_name.setText(f"File: {os.path.basename(fname)}")
            self.central_widget.setCurrentWidget(self.unlock_page)

    def handle_create_vault(self):
        password = self.setup_pass.text()
        ans1 = self.q1_ans.text()
        ans2 = self.q2_ans.text()
        if not password or not ans1 or not ans2:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return
        vault_structure, recoveryKey = self.aegis.create_new_vault(password, [ans1, ans2])
        self.generate_pdf(recoveryKey)
        fname, _ = QFileDialog.getSaveFileName(self, 'Save Vault', '.', "JSON Files (*.json)")
        if fname:
            with open(fname, 'w') as f:
                json.dump(vault_structure, f)
            QMessageBox.information(self, "Success", "Vault created! PDF Kit saved to folder.")
            self.central_widget.setCurrentIndex(0)

    def generate_pdf(self, recoveryKey):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="AegisPass - Emergency Recovery Kit", ln=1, align='C')
        pdf.ln(10)
        pdf.multi_cell(0, 10, txt=f"RECOVERY KEY:\n{recoveryKey}")
        try:
            pdf.output("AegisPass_Recovery_Kit.pdf")
        except Exception:
            QMessageBox.warning(self, "Warning", "Could not save PDF. Please write down the key!")

    def handle_unlock(self):
        if not self.current_file_path: return
        try:
            with open(self.current_file_path, 'r') as f:
                self.file_structure = json.load(f)
            if self.chk_recovery.isChecked():
                self.vault_data, self.dek = self.aegis.unlock_vault(
                    self.file_structure, recoveryKey=self.recovery_input.text()
                )
            else:
                self.vault_data, self.dek = self.aegis.unlock_vault(
                    self.file_structure, password=self.unlock_pass.text(),
                    answers=[self.unlock_q1.text(), self.unlock_q2.text()]
                )
            self.refresh_table()
            self.central_widget.setCurrentWidget(self.vault_page)
            self.unlock_pass.clear() 
            self.recovery_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

    def refresh_table(self):
        self.table.setRowCount(len(self.vault_data))
        for i, entry in enumerate(self.vault_data):
            self.table.setItem(i, 0, QTableWidgetItem(entry.get("service", "")))
            self.table.setItem(i, 1, QTableWidgetItem(entry.get("username", "")))
            
            if hasattr(self, 'chk_show_pass') and self.chk_show_pass.isChecked():
                pass_text = entry.get("password", "")
            else:
                pass_text = "********"
            
            self.table.setItem(i, 2, QTableWidgetItem(pass_text))

    def show_add_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Entry")
        layout = QFormLayout(dialog)
        inp_service = QLineEdit()
        inp_user = QLineEdit()
        inp_pass = QLineEdit()
        layout.addRow("Service:", inp_service)
        layout.addRow("Username:", inp_user)
        layout.addRow("Password:", inp_pass)
        btn_ok = QPushButton("Add")
        btn_ok.clicked.connect(lambda: dialog.accept())
        layout.addWidget(btn_ok)
        
        if dialog.exec():
            new_entry = {
                "service": inp_service.text(),
                "username": inp_user.text(),
                "password": inp_pass.text()
            }
            self.vault_data.append(new_entry)
            self.refresh_table()

    def save_vault_changes(self):
        if not self.current_file_path or not self.dek: 
            return
        try:
            folder = os.path.dirname(self.current_file_path)
            backup_folder = os.path.join(folder, "Aegis_Backups")
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)

            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = os.path.basename(self.current_file_path)
            backup_name = f"{filename}_{timestamp}.bak"
            backup_path = os.path.join(backup_folder, backup_name)
            shutil.copy2(self.current_file_path, backup_path)

            new_structure = self.aegis.encrypt_for_save(
                self.vault_data, self.dek, self.file_structure
            )
            with open(self.current_file_path, 'w') as f:
                json.dump(new_structure, f)
            QMessageBox.information(self, "Saved", "Vault updated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save: {str(e)}")

    def lock_vault(self):
        self.vault_data = []
        self.dek = None
        self.file_structure = None
        self.table.setRowCount(0)
        self.central_widget.setCurrentIndex(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AegisPassApp()
    window.show()
    sys.exit(app.exec())