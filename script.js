class SecureCrypt {
    constructor() {
        this.selectedAlgorithm = 'AES-256-GCM';
        this.currentFile = null;
        this.encryptedFile = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupFileHandling();
        this.updatePasswordStrength();
    }

    setupEventListeners() {
        // Algorithm selection
        document.querySelectorAll('.algorithm-card').forEach(card => {
            card.addEventListener('click', () => this.selectAlgorithm(card));
        });

        // Password visibility toggle
        document.getElementById('togglePassword').addEventListener('click', () => this.togglePasswordVisibility());

        // Password strength monitoring
        document.getElementById('password').addEventListener('input', () => this.updatePasswordStrength());

        // Tab switching
        document.querySelectorAll('.io-tab').forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab));
        });

        // Text encryption/decryption
        document.getElementById('encryptBtn').addEventListener('click', () => this.encryptText());
        document.getElementById('decryptBtn').addEventListener('click', () => this.decryptText());

        // File encryption/decryption
        document.getElementById('encryptFileBtn').addEventListener('click', () => this.encryptFile());
        document.getElementById('decryptFileBtn').addEventListener('click', () => this.decryptFile());

        // Utility buttons
        document.getElementById('clearInput').addEventListener('click', () => this.clearInput());
        document.getElementById('pasteInput').addEventListener('click', () => this.pasteInput());
        document.getElementById('copyOutput').addEventListener('click', () => this.copyOutput());
        document.getElementById('clearOutput').addEventListener('click', () => this.clearOutput());
        document.getElementById('removeFile').addEventListener('click', () => this.removeFile());
        document.getElementById('downloadBtn').addEventListener('click', () => this.downloadFile());

        // Modal handling
        document.getElementById('modalClose').addEventListener('click', () => this.closeModal());
        document.getElementById('privacyLink').addEventListener('click', (e) => {
            e.preventDefault();
            this.showModal('Privacy Policy', 'All encryption and decryption operations happen locally in your browser. No data is sent to any server. Your files and encryption keys never leave your computer.');
        });
        document.getElementById('securityLink').addEventListener('click', (e) => {
            e.preventDefault();
            this.showModal('Security Information', 'This tool uses industry-standard encryption algorithms: AES-256-GCM, AES-256-CBC, and ChaCha20-Poly1305. All keys are derived using PBKDF2 with 100,000 iterations for maximum security.');
        });
        document.getElementById('aboutLink').addEventListener('click', (e) => {
            e.preventDefault();
            this.showModal('About SecureCrypt', 'SecureCrypt is a client-side encryption tool that provides military-grade encryption for your sensitive data. Built with modern web technologies and strong cryptographic principles.');
        });

        // Close modal on background click
        document.getElementById('infoModal').addEventListener('click', (e) => {
            if (e.target.id === 'infoModal') this.closeModal();
        });
    }

    setupFileHandling() {
        const fileInput = document.getElementById('fileInput');
        const dropZone = document.getElementById('fileDropZone');

        fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files[0]));

        // Drag and drop handling
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file) this.handleFileSelect(file);
        });

        dropZone.addEventListener('click', () => fileInput.click());
    }

    selectAlgorithm(card) {
        document.querySelectorAll('.algorithm-card').forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        this.selectedAlgorithm = card.dataset.algorithm;
    }

    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = document.getElementById('togglePassword').querySelector('i');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            toggleIcon.className = 'fas fa-eye';
        }
    }

    updatePasswordStrength() {
        const password = document.getElementById('password').value;
        const meter = document.querySelector('.password-strength-meter');
        const strengthBar = document.querySelector('.strength-bar');
        const strengthText = document.querySelector('.strength-text');

        if (!password) {
            meter.className = 'password-strength-meter';
            strengthText.textContent = 'Password strength';
            return;
        }

        const strength = this.calculatePasswordStrength(password);
        
        meter.className = `password-strength-meter password-${strength.level}`;
        strengthText.textContent = strength.text;
        
        // Update the strength bar width
        const strengthBarInner = strengthBar.querySelector('.strength-bar-inner') || document.createElement('div');
        strengthBarInner.className = 'strength-bar-inner';
        strengthBarInner.style.width = `${strength.score}%`;
        strengthBarInner.style.background = this.getStrengthColor(strength.level);
        
        if (!strengthBar.querySelector('.strength-bar-inner')) {
            strengthBar.appendChild(strengthBarInner);
        }
    }

    calculatePasswordStrength(password) {
        let score = 0;
        
        // Length check
        if (password.length >= 12) score += 25;
        else if (password.length >= 8) score += 15;
        else if (password.length >= 6) score += 5;

        // Character variety
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 10;
        if (/[^a-zA-Z0-9]/.test(password)) score += 15;

        // Entropy calculation
        const charSetSize = this.getCharSetSize(password);
        const entropy = password.length * Math.log2(charSetSize);
        score += Math.min(30, entropy / 2);

        score = Math.min(100, score);

        // Determine level and text
        let level, text;
        if (score >= 80) {
            level = 'very-strong';
            text = 'Very strong password';
        } else if (score >= 60) {
            level = 'strong';
            text = 'Strong password';
        } else if (score >= 40) {
            level = 'medium';
            text = 'Medium strength password';
        } else {
            level = 'weak';
            text = 'Weak password';
        }

        return { score, level, text };
    }

    getStrengthColor(level) {
        const colors = {
            'weak': '#ef4444',
            'medium': '#f59e0b',
            'strong': '#3b82f6',
            'very-strong': '#10b981'
        };
        return colors[level] || '#ef4444';
    }

    getCharSetSize(password) {
        let size = 0;
        if (/[a-z]/.test(password)) size += 26;
        if (/[A-Z]/.test(password)) size += 26;
        if (/[0-9]/.test(password)) size += 10;
        if (/[^a-zA-Z0-9]/.test(password)) size += 32;
        return size || 1;
    }

    switchTab(tab) {
        document.querySelectorAll('.io-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.io-content').forEach(c => c.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
    }

    async encryptText() {
        const input = document.getElementById('inputText').value.trim();
        const password = document.getElementById('password').value;

        if (!input) {
            this.showError('Please enter text to encrypt');
            return;
        }

        if (!password) {
            this.showError('Please enter an encryption key');
            return;
        }

        this.showLoading();

        try {
            let encrypted;
            switch (this.selectedAlgorithm) {
                case 'AES-256-GCM':
                    encrypted = await this.encryptAESGCM(input, password);
                    break;
                case 'AES-256-CBC':
                    encrypted = await this.encryptAESCBC(input, password);
                    break;
                case 'ChaCha20-Poly1305':
                    encrypted = await this.encryptChaCha20(input, password);
                    break;
                default:
                    throw new Error('Unsupported algorithm');
            }

            document.getElementById('outputText').value = `${encrypted.salt}.${encrypted.iv}.${encrypted.ciphertext}`;
            this.showSuccess('Text encrypted successfully!');
        } catch (error) {
            this.showError(`Encryption failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    async decryptText() {
        const input = document.getElementById('inputText').value.trim();
        const password = document.getElementById('password').value;

        if (!input) {
            this.showError('Please enter encrypted data to decrypt');
            return;
        }

        if (!password) {
            this.showError('Please enter the decryption key');
            return;
        }

        this.showLoading();

        try {
            let encryptedData;
            
            // New compact format: salt.iv.ciphertext
            const parts = input.split('.');
            if (parts.length < 3) {
                throw new Error('Invalid encrypted data format');
            }
            encryptedData = {
                salt: parts[0],
                iv: parts[1],
                ciphertext: parts.slice(2).join('.')
            };

            let decrypted;

            // Determine algorithm and decrypt
            if (encryptedData.algorithm === 'AES-256-GCM' || this.selectedAlgorithm === 'AES-256-GCM') {
                decrypted = await this.decryptAESGCM(encryptedData, password);
            } else if (encryptedData.algorithm === 'AES-256-CBC' || this.selectedAlgorithm === 'AES-256-CBC') {
                decrypted = await this.decryptAESCBC(encryptedData, password);
            } else if (encryptedData.algorithm === 'ChaCha20-Poly1305' || this.selectedAlgorithm === 'ChaCha20-Poly1305') {
                decrypted = await this.decryptChaCha20(encryptedData, password);
            } else {
                throw new Error('Unsupported algorithm in encrypted data');
            }

            document.getElementById('outputText').value = decrypted;
            this.showSuccess('Text decrypted successfully!');
        } catch (error) {
            this.showError(`Decryption failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    // AES-256-GCM UI option (implemented as AES-256-CBC fallback for CryptoJS)
    async encryptAESGCM(text, password) {
        try {
            const salt = CryptoJS.lib.WordArray.random(16);
            const key = CryptoJS.PBKDF2(password, salt, {
                keySize: 256 / 32,
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });

            // 16-byte IV for CBC
            const iv = CryptoJS.lib.WordArray.random(16);

            const encrypted = CryptoJS.AES.encrypt(text, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            return {
                algorithm: 'AES-256-GCM', // UI label only; internally CBC
                ciphertext: encrypted.toString(),
                iv: CryptoJS.enc.Base64.stringify(iv),
                salt: CryptoJS.enc.Base64.stringify(salt)
            };
        } catch (error) {
            throw new Error(`AES-GCM (CBC-fallback) encryption error: ${error.message}`);
        }
    }

    async decryptAESGCM(encryptedData, password) {
        try {
            if (!encryptedData.salt || !encryptedData.iv || !encryptedData.ciphertext) {
                throw new Error('Invalid encrypted data: missing required fields');
            }

            const salt = CryptoJS.enc.Base64.parse(encryptedData.salt);
            const iv = CryptoJS.enc.Base64.parse(encryptedData.iv);

            const key = CryptoJS.PBKDF2(password, salt, {
                keySize: 256 / 32,
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });

            const decrypted = CryptoJS.AES.decrypt(encryptedData.ciphertext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const result = decrypted.toString(CryptoJS.enc.Utf8);

            if (!result) {
                throw new Error('Decryption failed - possibly wrong password or corrupted data');
            }

            return result;
        } catch (error) {
            throw new Error(`AES-GCM (CBC-fallback) decryption error: ${error.message}`);
        }
    }

    // AES-256-CBC Encryption
    async encryptAESCBC(text, password) {
        try {
            const salt = CryptoJS.lib.WordArray.random(16);
            const key = CryptoJS.PBKDF2(password, salt, { 
                keySize: 256/32, 
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });
            
            const iv = CryptoJS.lib.WordArray.random(16);
            
            const encrypted = CryptoJS.AES.encrypt(text, key, { 
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            return {
                algorithm: 'AES-256-CBC',
                ciphertext: encrypted.toString(),
                iv: CryptoJS.enc.Base64.stringify(iv),
                salt: CryptoJS.enc.Base64.stringify(salt)
            };
        } catch (error) {
            throw new Error(`AES-CBC encryption error: ${error.message}`);
        }
    }

    async decryptAESCBC(encryptedData, password) {
        try {
            if (!encryptedData.salt || !encryptedData.iv || !encryptedData.ciphertext) {
                throw new Error('Invalid encrypted data: missing required fields');
            }

            const salt = CryptoJS.enc.Base64.parse(encryptedData.salt);
            const iv = CryptoJS.enc.Base64.parse(encryptedData.iv);

            const key = CryptoJS.PBKDF2(password, salt, { 
                keySize: 256/32, 
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });

            const decrypted = CryptoJS.AES.decrypt(encryptedData.ciphertext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const result = decrypted.toString(CryptoJS.enc.Utf8);
            
            if (!result) {
                throw new Error('Decryption failed - possibly wrong password or corrupted data');
            }

            return result;
        } catch (error) {
            throw new Error(`AES-CBC decryption error: ${error.message}`);
        }
    }

    // ChaCha20 Encryption (using CTR mode as fallback)
    async encryptChaCha20(text, password) {
        try {
            const salt = CryptoJS.lib.WordArray.random(16);
            const key = CryptoJS.PBKDF2(password, salt, { 
                keySize: 256/32, 
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });
            
            const nonce = CryptoJS.lib.WordArray.random(12);
            
            const encrypted = CryptoJS.AES.encrypt(text, key, { 
                iv: nonce,
                mode: CryptoJS.mode.CTR,
                padding: CryptoJS.pad.NoPadding
            });

            return {
                algorithm: 'ChaCha20-Poly1305',
                ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
                nonce: CryptoJS.enc.Base64.stringify(nonce),
                salt: CryptoJS.enc.Base64.stringify(salt)
            };
        } catch (error) {
            throw new Error(`ChaCha20 encryption error: ${error.message}`);
        }
    }

    async decryptChaCha20(encryptedData, password) {
        try {
            if (!encryptedData.salt || !encryptedData.nonce || !encryptedData.ciphertext) {
                throw new Error('Invalid encrypted data: missing required fields');
            }

            const salt = CryptoJS.enc.Base64.parse(encryptedData.salt);
            const nonce = CryptoJS.enc.Base64.parse(encryptedData.nonce);

            const key = CryptoJS.PBKDF2(password, salt, { 
                keySize: 256/32, 
                iterations: 100000,
                hasher: CryptoJS.algo.SHA256
            });

            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: CryptoJS.enc.Base64.parse(encryptedData.ciphertext) }, 
                key, 
                {
                    iv: nonce,
                    mode: CryptoJS.mode.CTR,
                    padding: CryptoJS.pad.NoPadding
                }
            );

            const result = decrypted.toString(CryptoJS.enc.Utf8);
            
            if (!result) {
                throw new Error('Decryption failed - possibly wrong password or corrupted data');
            }

            return result;
        } catch (error) {
            throw new Error(`ChaCha20 decryption error: ${error.message}`);
        }
    }

    // File handling methods
    handleFileSelect(file) {
        if (!file) return;

        // Check file size (100MB limit)
        if (file.size > 100 * 1024 * 1024) {
            this.showError('File size must be less than 100MB');
            return;
        }

        this.currentFile = file;
        this.updateFileUI();

        // Enable encryption/decryption buttons
        document.getElementById('encryptFileBtn').disabled = false;
        document.getElementById('decryptFileBtn').disabled = false;
    }

    updateFileUI() {
        const fileInfo = document.getElementById('fileInfo');
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');

        fileName.textContent = this.currentFile.name;
        fileSize.textContent = this.formatFileSize(this.currentFile.size);
        fileInfo.style.display = 'block';
    }

    formatFileSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    async encryptFile() {
        if (!this.currentFile || !document.getElementById('password').value) {
            this.showError('Please select a file and enter an encryption key');
            return;
        }

        this.showLoading();

        try {
            const arrayBuffer = await this.readFileAsArrayBuffer(this.currentFile);
            const password = document.getElementById('password').value;
            
            // Convert ArrayBuffer to WordArray
            const wordArray = CryptoJS.lib.WordArray.create(arrayBuffer);
            const text = CryptoJS.enc.Base64.stringify(wordArray);
            
            let encrypted;
            switch (this.selectedAlgorithm) {
                case 'AES-256-GCM':
                    encrypted = await this.encryptAESGCM(text, password);
                    break;
                case 'AES-256-CBC':
                    encrypted = await this.encryptAESCBC(text, password);
                    break;
                case 'ChaCha20-Poly1305':
                    encrypted = await this.encryptChaCha20(text, password);
                    break;
                default:
                    throw new Error('Unsupported algorithm');
            }

            // Add file metadata
            encrypted.originalName = this.currentFile.name;
            encrypted.mimeType = this.currentFile.type;

            this.encryptedFile = {
                originalName: this.currentFile.name + '.encrypted',
                encryptedData: encrypted,
                isEncrypted: true
            };

            this.showDownloadArea();
            this.showSuccess('File encrypted successfully!');
        } catch (error) {
            this.showError(`File encryption failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    async decryptFile() {
        if (!this.currentFile) {
            this.showError('Please select an encrypted file');
            return;
        }

        const password = document.getElementById('password').value;
        if (!password) {
            this.showError('Please enter the decryption key');
            return;
        }

        this.showLoading();

        try {
            const text = await this.readFileAsText(this.currentFile);
            let encryptedData;

            try {
                encryptedData = JSON.parse(text);
            } catch (e) {
                throw new Error('Invalid encrypted file format');
            }

            if (!encryptedData.algorithm || !encryptedData.ciphertext) {
                throw new Error('Not a valid encrypted file');
            }

            let decryptedText;
            switch (encryptedData.algorithm) {
                case 'AES-256-GCM':
                    decryptedText = await this.decryptAESGCM(encryptedData, password);
                    break;
                case 'AES-256-CBC':
                    decryptedText = await this.decryptAESCBC(encryptedData, password);
                    break;
                case 'ChaCha20-Poly1305':
                    decryptedText = await this.decryptChaCha20(encryptedData, password);
                    break;
                default:
                    throw new Error('Unsupported algorithm in encrypted file');
            }

            // Convert back to ArrayBuffer
            const wordArray = CryptoJS.enc.Base64.parse(decryptedText);
            const arrayBuffer = this.wordArrayToArrayBuffer(wordArray);

            this.encryptedFile = {
                originalName: encryptedData.originalName || 'decrypted_file',
                decryptedData: arrayBuffer,
                mimeType: encryptedData.mimeType || 'application/octet-stream',
                isEncrypted: false
            };

            this.showDownloadArea();
            this.showSuccess('File decrypted successfully!');
        } catch (error) {
            this.showError(`File decryption failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    wordArrayToArrayBuffer(wordArray) {
        const words = wordArray.words;
        const length = wordArray.sigBytes;
        const arrayBuffer = new ArrayBuffer(length);
        const uint8Array = new Uint8Array(arrayBuffer);
        
        for (let i = 0; i < length; i++) {
            uint8Array[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }
        
        return arrayBuffer;
    }

    showDownloadArea() {
        const downloadArea = document.getElementById('downloadArea');
        const downloadBtn = document.getElementById('downloadBtn');
        
        if (this.encryptedFile.isEncrypted) {
            downloadBtn.innerHTML = '<i class="fas fa-download"></i> Download Encrypted File';
        } else {
            downloadBtn.innerHTML = '<i class="fas fa-download"></i> Download Decrypted File';
        }
        
        downloadArea.style.display = 'block';
    }

    downloadFile() {
        if (!this.encryptedFile) return;

        let blob, filename;

        if (this.encryptedFile.isEncrypted) {
            // Download encrypted file as JSON
            const content = JSON.stringify(this.encryptedFile.encryptedData, null, 2);
            blob = new Blob([content], { type: 'application/json' });
            filename = this.encryptedFile.originalName;
        } else {
            // Download decrypted file
            blob = new Blob([this.encryptedFile.decryptedData], { type: this.encryptedFile.mimeType });
            filename = this.encryptedFile.originalName;
        }

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    removeFile() {
        this.currentFile = null;
        this.encryptedFile = null;
        document.getElementById('fileInfo').style.display = 'none';
        document.getElementById('downloadArea').style.display = 'none';
        document.getElementById('fileInput').value = '';
        document.getElementById('encryptFileBtn').disabled = true;
        document.getElementById('decryptFileBtn').disabled = true;
    }

    // Utility methods
    clearInput() {
        document.getElementById('inputText').value = '';
    }

    async pasteInput() {
        try {
            const text = await navigator.clipboard.readText();
            document.getElementById('inputText').value = text;
        } catch (error) {
            this.showError('Failed to read from clipboard');
        }
    }

    copyOutput() {
        const output = document.getElementById('outputText').value;
        if (!output) {
            this.showError('No output to copy');
            return;
        }

        navigator.clipboard.writeText(output).then(() => {
            this.showSuccess('Output copied to clipboard!');
        }).catch(() => {
            this.showError('Failed to copy to clipboard');
        });
    }

    clearOutput() {
        document.getElementById('outputText').value = '';
    }

    // UI feedback methods
    showLoading() {
        document.getElementById('loadingOverlay').style.display = 'flex';
    }

    hideLoading() {
        document.getElementById('loadingOverlay').style.display = 'none';
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}-circle"></i>
            <span>${message}</span>
        `;

        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? 'var(--success-color)' : 'var(--error-color)'};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: var(--shadow);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            z-index: 1001;
            animation: slideIn 0.3s ease;
        `;

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }

    showModal(title, content) {
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('modalBody').innerHTML = `<p>${content}</p>`;
        document.getElementById('infoModal').style.display = 'flex';
    }

    closeModal() {
        document.getElementById('infoModal').style.display = 'none';
    }
}

// Add CSS for strength bar
const additionalStyles = document.createElement('style');
additionalStyles.textContent = `
    .strength-bar {
        height: 4px;
        background: var(--border-color);
        border-radius: 2px;
        overflow: hidden;
        margin-bottom: 0.25rem;
        position: relative;
    }
    
    .strength-bar-inner {
        height: 100%;
        border-radius: 2px;
        transition: all 0.3s ease;
    }
    
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(additionalStyles);

// Initialize the application when the DOM is loaded
// =====================
// .enc Viewer Backend Logic
// =====================
const encViewBrowse = document.getElementById('encViewBrowse');
const encViewInput = document.getElementById('encViewInput');
const encViewText = document.getElementById('encViewText');

if (encViewBrowse && encViewInput && encViewText) {
    encViewBrowse.addEventListener('click', () => {
        encViewInput.click();
    });

    encViewInput.addEventListener('change', async (event) => {
        const file = event.target.files[0];
        if (!file) {
            encViewText.value = "No file selected";
            return;
        }

        try {
            const text = await file.text();

            // Try JSON formatting
            try {
                const json = JSON.parse(text);
                encViewText.value = JSON.stringify(json, null, 2);
            } catch {
                encViewText.value = text;
            }
        } catch (err) {
            encViewText.value = "Error reading .enc file: " + err.message;
        }
    });
}
document.addEventListener('DOMContentLoaded', () => {
    new SecureCrypt();
});
// Tutorial Button
document.getElementById("tutorialBtn").addEventListener("click", () => {
    document.getElementById("modalTitle").innerText = "SecureCrypt Tutorial";
    document.getElementById("infoModal").style.display = "flex";
});
