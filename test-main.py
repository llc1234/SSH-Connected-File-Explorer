#!/usr/bin/env python3
"""
PySide6 SSH File Explorer
- Left: local filesystem (QFileSystemModel)
- Right: remote filesystem (custom QTreeWidget populated via Paramiko SFTP)
- Manual SSH credentials (no saved sessions)
- Upload/Download files via SFTP (background threads)
- Open files with system default app
- No in-app editor or embedded media viewer
"""

import os
import stat
import tempfile
import traceback
from functools import partial

from PySide6.QtCore import (Qt, QDir, QModelIndex, QObject, Signal, Slot,
                            QRunnable, QThreadPool, QUrl)
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QSplitter, QTreeView, QFileSystemModel,
    QWidget, QVBoxLayout, QLabel, QToolBar, QLineEdit, QPushButton,
    QHBoxLayout, QStatusBar, QMessageBox, QInputDialog, QMenu, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QProgressDialog, QDialog, QFormLayout,
    QSpinBox, QCheckBox
)
from PySide6.QtGui import QDesktopServices

# Paramiko import
try:
    import paramiko
except Exception as e:
    paramiko = None

APP_TITLE = "SSH File Explorer (PySide6 + Paramiko)"


# -------------------------
# Worker infrastructure
# -------------------------
class WorkerSignals(QObject):
    started = Signal()
    finished = Signal()
    error = Signal(str)
    progress = Signal(int)  # percent
    message = Signal(str)


class SFTPWorker(QRunnable):
    """
    QRunnable performing SFTP actions (get/put/list)
    mode: 'get' or 'put' or 'list' or 'stat'
    kwargs depends on mode
    Emits signals for progress and completion.
    """

    def __init__(self, sftp, mode, signals: WorkerSignals, **kwargs):
        super().__init__()
        self.sftp = sftp
        self.mode = mode
        self.signals = signals
        self.kwargs = kwargs

    def run(self):
        try:
            self.signals.started.emit()
            if self.mode == "get":
                remote = self.kwargs["remote_path"]
                local = self.kwargs["local_path"]
                self._sftp_get(remote, local)
                self.signals.message.emit(f"Downloaded: {remote} → {local}")
            elif self.mode == "put":
                local = self.kwargs["local_path"]
                remote = self.kwargs["remote_path"]
                self._sftp_put(local, remote)
                self.signals.message.emit(f"Uploaded: {local} → {remote}")
            elif self.mode == "list":
                path = self.kwargs["path"]
                entries = self.sftp.listdir_attr(path)
                self.signals.finished.emit()
                # return entries via message as serialized? Better to handle list externally.
            elif self.mode == "stat":
                path = self.kwargs["path"]
                st = self.sftp.stat(path)
                self.signals.finished.emit()
            else:
                raise RuntimeError("Unknown SFTPWorker mode")
        except Exception as e:
            tb = traceback.format_exc()
            self.signals.error.emit(f"{e}\n{tb}")
        finally:
            self.signals.finished.emit()

    def _sftp_get(self, remote_path, local_path):
        # Try to use sftp.get with callback for progress
        # Determine size for progress percent
        try:
            size = self.sftp.stat(remote_path).st_size
        except Exception:
            size = 0

        transferred = 0

        def callback(transferred_bytes, total_bytes):
            nonlocal transferred
            transferred = transferred_bytes
            if total_bytes:
                pct = int((transferred_bytes / total_bytes) * 100)
            elif size:
                pct = int((transferred_bytes / size) * 100)
            else:
                pct = 0
            self.signals.progress.emit(max(0, min(100, pct)))

        self.sftp.get(remote_path, local_path, callback=callback)

    def _sftp_put(self, local_path, remote_path):
        try:
            size = os.path.getsize(local_path)
        except Exception:
            size = 0

        transferred = 0

        def callback(transferred_bytes, total_bytes):
            nonlocal transferred
            transferred = transferred_bytes
            if total_bytes:
                pct = int((transferred_bytes / total_bytes) * 100)
            elif size:
                pct = int((transferred_bytes / size) * 100)
            else:
                pct = 0
            self.signals.progress.emit(max(0, min(100, pct)))

        self.sftp.put(local_path, remote_path, callback=callback)


# -------------------------
# SSH / SFTP wrapper
# -------------------------
class SSHSession(QObject):
    connected = Signal()
    disconnected = Signal()
    error = Signal(str)

    def __init__(self):
        super().__init__()
        self.client = None
        self.sftp = None

    def connect(self, hostname, port, username, password, pkey_path=None, look_for_keys=False):
        if paramiko is None:
            self.error.emit("Paramiko library is not installed. Install with: pip install paramiko")
            return False
        try:
            self.client = paramiko.SSHClient()
            # WARNING: AutoAddPolicy is convenient, but in secure environments consider stricter policy.
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if pkey_path:
                pkey = paramiko.RSAKey.from_private_key_file(pkey_path)
                self.client.connect(hostname, port=port, username=username, pkey=pkey, look_for_keys=look_for_keys)
            else:
                self.client.connect(hostname, port=port, username=username, password=password, look_for_keys=look_for_keys)
            self.sftp = self.client.open_sftp()
            self.connected.emit()
            return True
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"SSH connect failed: {e}\n{tb}")
            self.disconnect()
            return False

    def disconnect(self):
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.sftp = None
        self.client = None
        self.disconnected.emit()

    def is_connected(self):
        return self.sftp is not None


# -------------------------
# SSH Credentials Dialog
# -------------------------
class SSHDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to SSH Server")
        self.resize(420, 180)
        self.host_edit = QLineEdit()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pkey_edit = QLineEdit()
        self.pkey_button = QPushButton("Browse")
        self.pkey_button.clicked.connect(self._pick_pkey)
        self.look_for_keys_check = QCheckBox("Allow looking for keys")
        form = QFormLayout()
        form.addRow("Host:", self.host_edit)
        form.addRow("Port:", self.port_spin)
        form.addRow("Username:", self.user_edit)
        form.addRow("Password:", self.pass_edit)
        h = QHBoxLayout()
        h.addWidget(self.pkey_edit)
        h.addWidget(self.pkey_button)
        form.addRow("Private key file (optional):", h)
        form.addRow("", self.look_for_keys_check)

        btn_ok = QPushButton("Connect")
        btn_cancel = QPushButton("Cancel")
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btn_h = QHBoxLayout()
        btn_h.addStretch()
        btn_h.addWidget(btn_ok)
        btn_h.addWidget(btn_cancel)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addLayout(btn_h)
        self.setLayout(layout)

    def _pick_pkey(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select private key file", QDir.homePath())
        if path:
            self.pkey_edit.setText(path)

    def get_credentials(self):
        return {
            "host": self.host_edit.text().strip(),
            "port": int(self.port_spin.value()),
            "username": self.user_edit.text().strip(),
            "password": self.pass_edit.text(),
            "pkey": self.pkey_edit.text().strip() or None,
            "look_for_keys": self.look_for_keys_check.isChecked()
        }


# -------------------------
# Remote tree widget helper
# -------------------------
def is_dir_mode(mode):
    return stat.S_ISDIR(mode)


class RemoteTreeWidget(QTreeWidget):
    """
    QTreeWidget-based remote browser.
    Each QTreeWidgetItem stores full remote path in Qt.UserRole data.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(["Name", "Type"])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)
        self.itemExpanded.connect(self._on_item_expanded)
        self.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.ssh_session = None
        self.threadpool = QThreadPool.globalInstance()
        self.populate_root_done = {}  # cache for expanded nodes

    def set_ssh_session(self, ssh_session: SSHSession):
        self.ssh_session = ssh_session
        self.clear()
        self.populate_root_done.clear()
        if ssh_session and ssh_session.is_connected():
            # add root ("/") item
            root_item = QTreeWidgetItem(self, ["/", "Folder"])
            root_item.setData(0, Qt.UserRole, "/")
            root_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            self.addTopLevelItem(root_item)

    def _on_item_expanded(self, item: QTreeWidgetItem):
        path = item.data(0, Qt.UserRole)
        if path is None:
            return
        # Avoid repopulating if already done
        if item in self.populate_root_done:
            return
        self._populate_children(item, path)
        self.populate_root_done[item] = True

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        path = item.data(0, Qt.UserRole)
        if path is None:
            return
        # If file -> prompt to download then open
        item_type = item.text(1)
        if item_type != "Folder":
            # Download to temp then open
            if not self.ssh_session or not self.ssh_session.is_connected():
                QMessageBox.warning(self, "Not connected", "SSH/SFTP session not connected.")
                return
            tmpdir = tempfile.gettempdir()
            local_temp_path = os.path.join(tmpdir, os.path.basename(path))
            signals = WorkerSignals()
            dlg = QProgressDialog(f"Downloading {path}...", "Cancel", 0, 100, self)
            dlg.setWindowModality(Qt.WindowModal)
            signals.progress.connect(dlg.setValue)
            signals.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
            signals.finished.connect(dlg.close)

            worker = SFTPWorker(self.ssh_session.sftp, "get", signals,
                                remote_path=path, local_path=local_temp_path)
            self.threadpool.start(worker)
            dlg.exec()
            # If file present open it
            if os.path.exists(local_temp_path):
                QDesktopServices.openUrl(QUrl.fromLocalFile(local_temp_path))
        else:
            # folder - expand
            item.setExpanded(True)

    def refresh_path(self, path="/"):
        # Clear and repopulate root
        self.clear()
        self.populate_root_done.clear()
        root_item = QTreeWidgetItem(self, [path, "Folder"])
        root_item.setData(0, Qt.UserRole, path)
        root_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        self.addTopLevelItem(root_item)
        root_item.setExpanded(True)

    def _populate_children(self, parent_item: QTreeWidgetItem, path: str):
        # Clear any placeholder children
        parent_item.takeChildren()
        if not self.ssh_session or not self.ssh_session.is_connected():
            return
        try:
            entries = self.ssh_session.sftp.listdir_attr(path)
        except Exception as e:
            QMessageBox.critical(self, "SFTP Error", f"Failed to list directory {path}:\n{e}")
            return
        # Sort directories first, then files
        dirs = []
        files = []
        for attr in entries:
            name = attr.filename
            if name in (".", ".."):
                continue
            is_dir = is_dir_mode(attr.st_mode)
            if is_dir:
                dirs.append((name, attr))
            else:
                files.append((name, attr))
        dirs.sort(key=lambda x: x[0].lower())
        files.sort(key=lambda x: x[0].lower())
        for name, attr in dirs + files:
            full = path.rstrip("/") + "/" + name if path != "/" else "/" + name
            typ = "Folder" if is_dir_mode(attr.st_mode) else "File"
            item = QTreeWidgetItem(parent_item, [name, typ])
            item.setData(0, Qt.UserRole, full)
            if typ == "Folder":
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

    def _on_context_menu(self, pos):
        item = self.itemAt(pos)
        menu = QMenu(self)
        if item:
            path = item.data(0, Qt.UserRole)
            typ = item.text(1)
            if typ == "Folder":
                action_refresh = QAction("Refresh", self)
                action_refresh.triggered.connect(lambda: self._refresh_item(item))
                menu.addAction(action_refresh)
                action_download_here = QAction("Download folder to local...", self)
                action_download_here.triggered.connect(lambda: self._download_folder_to_local(item))
                menu.addAction(action_download_here)
                action_upload_here = QAction("Upload file(s) here...", self)
                action_upload_here.triggered.connect(lambda: self._upload_files_to_remote(item))
                menu.addAction(action_upload_here)
            else:
                action_download = QAction("Download file to local...", self)
                action_download.triggered.connect(lambda: self._download_file(item))
                menu.addAction(action_download)
            action_open = QAction("Open with default app (download if needed)", self)
            action_open.triggered.connect(lambda: self._on_item_double_clicked(item, 0))
            menu.addAction(action_open)
        else:
            # empty space
            if self.ssh_session and self.ssh_session.is_connected():
                action_upload = QAction("Upload file(s) to remote root...", self)
                action_upload.triggered.connect(lambda: self._upload_files_to_remote(None))
                menu.addAction(action_upload)
        menu.exec(self.viewport().mapToGlobal(pos))

    def _refresh_item(self, item: QTreeWidgetItem):
        path = item.data(0, Qt.UserRole)
        if not path:
            return
        # Force re-populate
        if item in self.populate_root_done:
            del self.populate_root_done[item]
        self._populate_children(item, path)

    # Context actions:
    def _download_file(self, item: QTreeWidgetItem):
        path = item.data(0, Qt.UserRole)
        if not path:
            return
        local_dir = QFileDialog.getExistingDirectory(self, "Select local folder to download into", QDir.homePath())
        if not local_dir:
            return
        local_path = os.path.join(local_dir, os.path.basename(path))
        self._start_download(path, local_path)

    def _download_folder_to_local(self, item: QTreeWidgetItem):
        path = item.data(0, Qt.UserRole)
        if not path:
            return
        local_dir = QFileDialog.getExistingDirectory(self, "Select parent local folder to download folder into", QDir.homePath())
        if not local_dir:
            return
        # We'll download folder by creating remote folder name under local_dir and recursively downloading.
        dest = os.path.join(local_dir, os.path.basename(path.rstrip("/")))
        os.makedirs(dest, exist_ok=True)
        self._download_folder_recursive(path, dest)

    def _upload_files_to_remote(self, item: QTreeWidgetItem):
        # choose files locally
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to upload", QDir.homePath())
        if not files:
            return
        if item:
            remote_dir = item.data(0, Qt.UserRole)
        else:
            # root or choose remote path
            remote_dir, ok = QInputDialog.getText(self, "Remote path", "Enter remote directory path (e.g. /home/user):", text="/")
            if not ok or not remote_dir:
                return
        for f in files:
            remote_path = remote_dir.rstrip("/") + "/" + os.path.basename(f)
            self._start_upload(f, remote_path)

    def _download_folder_recursive(self, remote_path, local_path):
        """
        Walk remote directory and download files. This implementation uses a naive recursion
        and enqueues downloads one by one (could be enhanced with concurrency).
        """
        if not self.ssh_session or not self.ssh_session.is_connected():
            QMessageBox.warning(self, "Not connected", "SFTP session not connected.")
            return
        try:
            entries = self.ssh_session.sftp.listdir_attr(remote_path)
        except Exception as e:
            QMessageBox.critical(self, "SFTP Error", f"Failed listing {remote_path}: {e}")
            return
        for attr in entries:
            name = attr.filename
            if name in (".", ".."):
                continue
            rfull = remote_path.rstrip("/") + "/" + name
            lfull = os.path.join(local_path, name)
            if is_dir_mode(attr.st_mode):
                os.makedirs(lfull, exist_ok=True)
                self._download_folder_recursive(rfull, lfull)
            else:
                self._start_download(rfull, lfull)

    def _start_download(self, remote_path, local_path):
        if not self.ssh_session or not self.ssh_session.is_connected():
            QMessageBox.warning(self, "Not connected", "SFTP session not connected.")
            return
        signals = WorkerSignals()
        dlg = QProgressDialog(f"Downloading {remote_path} ...", "Cancel", 0, 100, self)
        dlg.setWindowModality(Qt.WindowModal)
        signals.progress.connect(dlg.setValue)
        signals.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        # after finished - show message in parent window statusbar via signals.message
        signals.message.connect(lambda m: self.window().statusBar().showMessage(m, 8000))
        worker = SFTPWorker(self.ssh_session.sftp, "get", signals, remote_path=remote_path, local_path=local_path)
        self.threadpool.start(worker)
        dlg.exec()

    def _start_upload(self, local_path, remote_path):
        if not self.ssh_session or not self.ssh_session.is_connected():
            QMessageBox.warning(self, "Not connected", "SFTP session not connected.")
            return
        signals = WorkerSignals()
        dlg = QProgressDialog(f"Uploading {local_path} ...", "Cancel", 0, 100, self)
        dlg.setWindowModality(Qt.WindowModal)
        signals.progress.connect(dlg.setValue)
        signals.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        signals.message.connect(lambda m: self.window().statusBar().showMessage(m, 8000))
        worker = SFTPWorker(self.ssh_session.sftp, "put", signals, local_path=local_path, remote_path=remote_path)
        self.threadpool.start(worker)
        dlg.exec()


# -------------------------
# Main Window
# -------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 700)
        self.threadpool = QThreadPool.globalInstance()
        self.ssh_session = SSHSession()
        self.ssh_session.connected.connect(self._on_ssh_connected)
        self.ssh_session.disconnected.connect(self._on_ssh_disconnected)
        self.ssh_session.error.connect(lambda msg: self._show_message(msg, error=True))

        self._create_ui()

    def _create_ui(self):
        # Toolbar
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)

        action_connect = QAction("Connect", self)
        action_connect.triggered.connect(self._action_connect)
        toolbar.addAction(action_connect)

        action_disconnect = QAction("Disconnect", self)
        action_disconnect.triggered.connect(self._action_disconnect)
        toolbar.addAction(action_disconnect)

        toolbar.addSeparator()
        action_refresh_remote = QAction("Refresh Remote", self)
        action_refresh_remote.triggered.connect(self._action_refresh_remote)
        toolbar.addAction(action_refresh_remote)

        action_upload = QAction("Upload...", self)
        action_upload.triggered.connect(self._action_upload)
        toolbar.addAction(action_upload)

        action_download = QAction("Download...", self)
        action_download.triggered.connect(self._action_download)
        toolbar.addAction(action_download)

        # Central widgets: Splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left: local file system
        self.local_model = QFileSystemModel()
        self.local_model.setRootPath(QDir.rootPath())
        self.local_view = QTreeView()
        self.local_view.setModel(self.local_model)
        self.local_view.setRootIndex(self.local_model.index(QDir.homePath()))
        self.local_view.doubleClicked.connect(self._local_double_clicked)
        self.local_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.local_view.customContextMenuRequested.connect(self._local_context_menu)
        self.local_view.setHeaderHidden(False)
        self.local_view.setColumnWidth(0, 300)

        local_container = QWidget()
        local_layout = QVBoxLayout()
        local_layout.setContentsMargins(4, 4, 4, 4)
        local_layout.addWidget(QLabel("Local"))
        local_layout.addWidget(self.local_view)
        local_container.setLayout(local_layout)

        # Right: remote tree
        self.remote_tree = RemoteTreeWidget()
        self.remote_tree.setHeaderHidden(False)
        self.remote_tree.set_ssh_session(self.ssh_session)

        remote_container = QWidget()
        remote_layout = QVBoxLayout()
        remote_layout.setContentsMargins(4, 4, 4, 4)
        remote_layout.addWidget(QLabel("Remote"))
        remote_layout.addWidget(self.remote_tree)
        remote_container.setLayout(remote_layout)

        splitter.addWidget(local_container)
        splitter.addWidget(remote_container)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        self.setCentralWidget(splitter)

        # Status bar
        self.setStatusBar(QStatusBar())

    # -----------------------
    # Local actions
    # -----------------------
    def _local_double_clicked(self, index: QModelIndex):
        # If file -> open with default app
        if not index.isValid():
            return
        if self.local_model.isDir(index):
            return
        local_path = self.local_model.filePath(index)
        QDesktopServices.openUrl(QUrl.fromLocalFile(local_path))

    def _local_context_menu(self, pos):
        idx = self.local_view.indexAt(pos)
        menu = QMenu(self)
        if idx.isValid():
            # file or folder
            local_path = self.local_model.filePath(idx)
            if os.path.isdir(local_path):
                action_upload_here = QAction("Upload folder contents to remote...", self)
                action_upload_here.triggered.connect(lambda: self._upload_local_folder_to_remote(local_path))
                menu.addAction(action_upload_here)
            else:
                action_upload_file = QAction("Upload file to remote...", self)
                action_upload_file.triggered.connect(lambda: self._upload_local_file(local_path))
                menu.addAction(action_upload_file)
            action_open = QAction("Open with default app", self)
            action_open.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(local_path)))
            menu.addAction(action_open)
        else:
            action_upload = QAction("Upload file(s) to remote...", self)
            action_upload.triggered.connect(self._action_upload)
            menu.addAction(action_upload)
        menu.exec(self.local_view.viewport().mapToGlobal(pos))

    def _upload_local_file(self, local_path):
        # ask remote folder
        if not self.ssh_session.is_connected():
            QMessageBox.warning(self, "Not connected", "Connect to SSH first.")
            return
        # pick remote folder via input (could be enhanced)
        remote_dir, ok = QInputDialog.getText(self, "Remote directory", "Enter remote directory path:", text="/")
        if not ok or not remote_dir:
            return
        remote_path = remote_dir.rstrip("/") + "/" + os.path.basename(local_path)
        signals = WorkerSignals()
        dlg = QProgressDialog(f"Uploading {local_path} ...", "Cancel", 0, 100, self)
        dlg.setWindowModality(Qt.WindowModal)
        signals.progress.connect(dlg.setValue)
        signals.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        signals.message.connect(lambda m: self.statusBar().showMessage(m, 8000))
        worker = SFTPWorker(self.ssh_session.sftp, "put", signals, local_path=local_path, remote_path=remote_path)
        self.threadpool.start(worker)
        dlg.exec()

    def _upload_local_folder_to_remote(self, local_folder):
        if not self.ssh_session.is_connected():
            QMessageBox.warning(self, "Not connected", "Connect to SSH first.")
            return
        remote_dir, ok = QInputDialog.getText(self, "Remote directory", "Enter remote directory path to upload into:", text="/")
        if not ok or not remote_dir:
            return
        # iterate files and upload (no recursive by default - implement recursively)
        for root, dirs, files in os.walk(local_folder):
            rel = os.path.relpath(root, local_folder)
            target_remote_dir = (remote_dir.rstrip("/") + "/" + os.path.basename(local_folder) + ("" if rel == "." else "/" + rel.replace("\\", "/")))
            # try to create remote dirs (best-effort)
            try:
                self.ssh_session.sftp.mkdir(target_remote_dir)
            except Exception:
                pass
            for fname in files:
                local_path = os.path.join(root, fname)
                remote_path = target_remote_dir.rstrip("/") + "/" + fname
                self._start_upload_task(local_path, remote_path)

    def _start_upload_task(self, local_path, remote_path):
        signals = WorkerSignals()
        dlg = QProgressDialog(f"Uploading {local_path} ...", "Cancel", 0, 100, self)
        dlg.setWindowModality(Qt.WindowModal)
        signals.progress.connect(dlg.setValue)
        signals.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        signals.message.connect(lambda m: self.statusBar().showMessage(m, 8000))
        worker = SFTPWorker(self.ssh_session.sftp, "put", signals, local_path=local_path, remote_path=remote_path)
        self.threadpool.start(worker)
        dlg.exec()

    # -----------------------
    # Remote actions (toolbar)
    # -----------------------
    def _action_connect(self):
        dlg = SSHDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        creds = dlg.get_credentials()
        host = creds["host"]
        port = creds["port"]
        username = creds["username"]
        password = creds["password"]
        pkey = creds["pkey"]
        look_for_keys = creds["look_for_keys"]
        if not host or not username:
            QMessageBox.warning(self, "Missing", "Host and username are required.")
            return
        self.statusBar().showMessage("Connecting...")
        ok = self.ssh_session.connect(host, port, username, password, pkey_path=pkey, look_for_keys=look_for_keys)
        if not ok:
            # error signaled by session.error
            pass

    def _action_disconnect(self):
        self.ssh_session.disconnect()
        self.remote_tree.clear()
        self.statusBar().showMessage("Disconnected", 4000)

    @Slot()
    def _on_ssh_connected(self):
        self.remote_tree.set_ssh_session(self.ssh_session)
        self.remote_tree.refresh_path("/")
        self.statusBar().showMessage("Connected", 4000)

    @Slot()
    def _on_ssh_disconnected(self):
        self.remote_tree.clear()
        self.statusBar().showMessage("Disconnected", 4000)

    def _show_message(self, msg: str, error: bool = False):
        if error:
            QMessageBox.critical(self, "Error", msg)
            self.statusBar().showMessage("Error: " + (msg.splitlines()[0] if msg else ""), 8000)
        else:
            self.statusBar().showMessage(msg, 8000)

    def _action_refresh_remote(self):
        if not self.ssh_session.is_connected():
            QMessageBox.information(self, "Not connected", "Connect to a remote server first.")
            return
        self.remote_tree.refresh_path("/")

    def _action_upload(self):
        # upload selected local files to remote
        if not self.ssh_session.is_connected():
            QMessageBox.information(self, "Not connected", "Connect to a remote server first.")
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Select local files to upload", QDir.homePath())
        if not files:
            return
        remote_dir, ok = QInputDialog.getText(self, "Remote directory", "Enter remote directory path:", text="/")
        if not ok or not remote_dir:
            return
        for f in files:
            remote_path = remote_dir.rstrip("/") + "/" + os.path.basename(f)
            self._start_upload_task(f, remote_path)

    def _action_download(self):
        # download remote file or folder (user must enter remote path)
        if not self.ssh_session.is_connected():
            QMessageBox.information(self, "Not connected", "Connect to a remote server first.")
            return
        remote_path, ok = QInputDialog.getText(self, "Remote path", "Enter remote file path to download (full path):", text="/")
        if not ok or not remote_path:
            return
        local_dir = QFileDialog.getExistingDirectory(self, "Select local folder to download into", QDir.homePath())
        if not local_dir:
            return
        # If remote_path ends with slash or is a folder -> recursive download
        try:
            attr = self.ssh_session.sftp.stat(remote_path)
            if is_dir_mode(attr.st_mode):
                # recursive
                dest = os.path.join(local_dir, os.path.basename(remote_path.rstrip("/")))
                os.makedirs(dest, exist_ok=True)
                self.remote_tree._download_folder_recursive(remote_path, dest)
            else:
                local_path = os.path.join(local_dir, os.path.basename(remote_path))
                self.remote_tree._start_download(remote_path, local_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stat remote path: {e}")

    # Helpers
    def _action_refresh_ui(self):
        self.remote_tree.refresh_path("/")


def main():
    import sys
    app = QApplication(sys.argv)
    if paramiko is None:
        QMessageBox.critical(None, "Missing dependency", "Paramiko is not installed. Install with:\n\npip install paramiko")
        return 1
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
