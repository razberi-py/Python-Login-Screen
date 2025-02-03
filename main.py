import sys
import re
import bcrypt
import sqlite3
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QVBoxLayout, QLabel,
    QHBoxLayout, QStackedWidget, QGraphicsScene, QGraphicsView, QGraphicsTextItem,
    QProgressBar, QMessageBox, QCheckBox, QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QPropertyAnimation, QRect, QTimer, pyqtSignal, QObject, QEasingCurve
from PyQt5.QtGui import QFont, QColor, QPalette, QLinearGradient, QBrush

# Constants
DATABASE = 'users.db'
CONFIG_FILE = 'config.json'
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # in seconds

# Utility Functions
def hash_password(password):
    """Hash a password for storing."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    """Check hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def load_config():
    """Load configuration from a JSON file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_config(config):
    """Save configuration to a JSON file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

# Database Setup
def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Input Validators
def is_valid_email(email):
    """Validate email format."""
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b'
    return re.match(regex, email)

def password_strength(password):
    """Calculate password strength."""
    length = len(password) >= 8
    digit = re.search(r"\d", password) is not None
    uppercase = re.search(r"[A-Z]", password) is not None
    lowercase = re.search(r"[a-z]", password) is not None
    special = re.search(r"[@$!%*?&#]", password) is not None
    score = sum([length, digit, uppercase, lowercase, special])
    return score

# Custom Signals
class Communicate(QObject):
    switch_page = pyqtSignal(int)
    login_successful = pyqtSignal(str)
    login_failed = pyqtSignal(str)

# Main Application Window
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Login System")
        self.setGeometry(100, 100, 400, 500)
        self.comm = Communicate()
        self.comm.switch_page.connect(self.switch_page)
        self.init_ui()

    def init_ui(self):
        # Set overall style
        self.setStyleSheet("""
            QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QLineEdit, QCheckBox {
                background-color: #34495e;
                border: 2px solid #2980b9;
                border-radius: 10px;
                padding: 10px;
                color: #ecf0f1;
            }
            QPushButton {
                background-color: #2980b9;
                border: none;
                border-radius: 10px;
                padding: 10px;
                color: #ecf0f1;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3498db;
            }
            QLabel {
                color: #ecf0f1;
            }
            QProgressBar {
                border: 1px solid #2980b9;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #27ae60;
                width: 20px;
            }
        """)

        # Stacked Widget to hold multiple pages
        self.stacked_widget = QStackedWidget()
        self.login_page = LoginPage(self.comm)
        self.register_page = RegisterPage(self.comm)
        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.register_page)

        # Layout
        layout = QVBoxLayout()
        layout.addStretch(1)
        layout.addWidget(self.stacked_widget)
        layout.addStretch(1)
        self.setLayout(layout)

    def switch_page(self, index):
        """Switch between login and register pages with animation."""
        current_index = self.stacked_widget.currentIndex()
        if index == current_index:
            return
        # Simple fade transition
        self.animate_transition(current_index, index)
    
    def animate_transition(self, from_index, to_index):
        """Animate transition between pages."""
        self.stacked_widget.setCurrentIndex(to_index)
        self.stacked_widget.currentWidget().setWindowOpacity(0)
        animation = QPropertyAnimation(self.stacked_widget.currentWidget(), b"windowOpacity")
        animation.setDuration(500)
        animation.setStartValue(0)
        animation.setEndValue(1)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.start()


# Login Page
class LoginPage(QWidget):
    def __init__(self, comm):
        super().__init__()
        self.comm = comm
        self.attempts = 0
        self.locked_out = False
        self.lockout_timer = QTimer()
        self.lockout_timer.timeout.connect(self.unlock)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("Welcome Back!")
        title.setFont(QFont('Segoe UI', 24))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addSpacing(20)

        # Username/Email Field
        self.username_email = QLineEdit()
        self.username_email.setPlaceholderText("Username or Email")
        layout.addWidget(self.username_email)

        layout.addSpacing(10)

        # Password Field with Visibility Toggle
        password_layout = QHBoxLayout()
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password)

        self.show_password = QCheckBox("Show")
        self.show_password.stateChanged.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password)
        layout.addLayout(password_layout)

        layout.addSpacing(10)

        # Remember Me Checkbox
        self.remember_me = QCheckBox("Remember Me")
        layout.addWidget(self.remember_me)

        layout.addSpacing(10)

        # Login Button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        layout.addSpacing(10)

        # Password Recovery
        self.forgot_password = QPushButton("Forgot Password?")
        self.forgot_password.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #3498db;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #2980b9;
            }
        """)
        self.forgot_password.clicked.connect(self.forgot_password_func)
        layout.addWidget(self.forgot_password)

        layout.addStretch(1)

        # Switch to Register Page
        self.to_register = QPushButton("Don't have an account? Register")
        self.to_register.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ecf0f1;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #bdc3c7;
            }
        """)
        self.to_register.clicked.connect(lambda: self.comm.switch_page.emit(1))
        layout.addWidget(self.to_register)

        layout.addSpacing(20)

        self.setLayout(layout)

    def toggle_password_visibility(self, state):
        """Toggle password visibility."""
        if state == Qt.Checked:
            self.password.setEchoMode(QLineEdit.Normal)
        else:
            self.password.setEchoMode(QLineEdit.Password)

    def login(self):
        """Handle user login."""
        if self.locked_out:
            QMessageBox.warning(self, "Locked Out", "Too many failed attempts. Try again later.")
            return

        username_email = self.username_email.text()
        password = self.password.text()

        if not username_email or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=? OR email=?", (username_email, username_email))
        result = cursor.fetchone()
        conn.close()

        if result and check_password(password, result[0]):
            self.attempts = 0
            if self.remember_me.isChecked():
                config = load_config()
                config['remember_me'] = True
                config['user'] = username_email
                save_config(config)
            QMessageBox.information(self, "Success", "Login successful!")
            # Emit login_successful signal or handle session
        else:
            self.attempts += 1
            QMessageBox.warning(self, "Error", "Invalid credentials.")
            if self.attempts >= MAX_LOGIN_ATTEMPTS:
                self.lock_out()

    def lock_out(self):
        """Lock out the user after too many failed attempts."""
        self.locked_out = True
        QMessageBox.warning(self, "Locked Out", f"Too many failed attempts. Try again in {LOCKOUT_TIME} seconds.")
        self.lockout_timer.start(LOCKOUT_TIME * 1000)

    def unlock(self):
        """Unlock the user after lockout time."""
        self.locked_out = False
        self.attempts = 0
        self.lockout_timer.stop()

    def forgot_password_func(self):
        """Handle password recovery."""
        QMessageBox.information(self, "Password Recovery", "Password recovery is not implemented yet.")

# Registration Page
class RegisterPage(QWidget):
    def __init__(self, comm):
        super().__init__()
        self.comm = comm
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("Create Account")
        title.setFont(QFont('Segoe UI', 24))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addSpacing(20)

        # Username Field
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        layout.addWidget(self.username)

        layout.addSpacing(10)

        # Email Field
        self.email = QLineEdit()
        self.email.setPlaceholderText("Email")
        layout.addWidget(self.email)

        layout.addSpacing(10)

        # Password Field with Visibility Toggle
        password_layout = QHBoxLayout()
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.textChanged.connect(self.update_password_strength)
        password_layout.addWidget(self.password)

        self.show_password = QCheckBox("Show")
        self.show_password.stateChanged.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password)
        layout.addLayout(password_layout)

        layout.addSpacing(10)

        # Password Strength Indicator
        self.password_strength_label = QLabel("Password Strength:")
        layout.addWidget(self.password_strength_label)

        self.password_strength_bar = QProgressBar()
        self.password_strength_bar.setRange(0, 5)
        self.password_strength_bar.setValue(0)
        layout.addWidget(self.password_strength_bar)

        layout.addSpacing(10)

        # Register Button
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        layout.addStretch(1)

        # Switch to Login Page
        self.to_login = QPushButton("Already have an account? Login")
        self.to_login.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ecf0f1;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #bdc3c7;
            }
        """)
        self.to_login.clicked.connect(lambda: self.comm.switch_page.emit(0))
        layout.addWidget(self.to_login)

        layout.addSpacing(20)

        self.setLayout(layout)

    def toggle_password_visibility(self, state):
        """Toggle password visibility."""
        if state == Qt.Checked:
            self.password.setEchoMode(QLineEdit.Normal)
        else:
            self.password.setEchoMode(QLineEdit.Password)

    def update_password_strength(self, password):
        """Update password strength indicator."""
        strength = password_strength(password)
        self.password_strength_bar.setValue(strength)
        if strength <= 2:
            self.password_strength_bar.setStyleSheet("QProgressBar::chunk {background-color: red;}")
            self.password_strength_label.setText("Password Strength: Weak")
        elif strength == 3:
            self.password_strength_bar.setStyleSheet("QProgressBar::chunk {background-color: orange;}")
            self.password_strength_label.setText("Password Strength: Moderate")
        elif strength >= 4:
            self.password_strength_bar.setStyleSheet("QProgressBar::chunk {background-color: green;}")
            self.password_strength_label.setText("Password Strength: Strong")

    def register(self):
        """Handle user registration."""
        username = self.username.text()
        email = self.email.text()
        password = self.password.text()

        if not username or not email or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        if not is_valid_email(email):
            QMessageBox.warning(self, "Input Error", "Invalid email format.")
            return

        if password_strength(password) < 4:
            QMessageBox.warning(self, "Input Error", "Password is too weak.")
            return

        hashed = hash_password(password)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed))
            conn.commit()
            conn.close()
            QMessageBox.information(self, "Success", "Registration successful!")
            self.comm.switch_page.emit(0)
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Username or email already exists.")

# Animated Background (Optional: Can be enhanced or removed based on preference)
class AnimatedBackground(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setFixedHeight(100)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Add animated text
        self.text_item = QGraphicsTextItem("Secure Login System")
        font = QFont('Segoe UI', 30, QFont.Bold)
        self.text_item.setFont(font)
        self.text_item.setDefaultTextColor(QColor('#2980b9'))
        self.scene.addItem(self.text_item)
        self.text_item.setPos(-300, 20)

        # Animation
        self.animation = QPropertyAnimation(self.text_item, b'pos')
        self.animation.setDuration(10000)
        self.animation.setStartValue(QRect(-300, 20, 0, 0).topLeft())
        self.animation.setEndValue(QRect(800, 20, 0, 0).topLeft())
        self.animation.setLoopCount(-1)
        self.animation.setEasingCurve(QEasingCurve.Linear)
        self.animation.start()

# Main Execution
if __name__ == '__main__':
    init_db()
    app = QApplication(sys.argv)

    # Apply a darker palette for the entire application
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor("#2c3e50"))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor("#34495e"))
    dark_palette.setColor(QPalette.AlternateBase, QColor("#2c3e50"))
    dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor("#2980b9"))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Highlight, QColor("#2980b9"))
    dark_palette.setColor(QPalette.HighlightedText, Qt.white)
    app.setPalette(dark_palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
