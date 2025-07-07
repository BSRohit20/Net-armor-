# 🛡️ NET ARMOR - Digital Security Toolkit

**Live Demo:** 🌐 **[https://web-production-07c5d.up.railway.app/](https://web-production-07c5d.up.railway.app/)**

A comprehensive web-based digital security toolkit that provides essential cybersecurity tools accessible from any device, anywhere in the world. Originally developed as a PyQt5 desktop application, NET ARMOR has been converted to a modern web application for global accessibility.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit%20App-blue?style=for-the-badge&logo=railway)](https://web-production-07c5d.up.railway.app/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.1.3-purple?style=for-the-badge&logo=bootstrap)](https://getbootstrap.com/)

## 🚀 **Live Application Features**

### 🔐 **Core Security Tools**
- **[Password Manager](https://web-production-07c5d.up.railway.app/password-manager)** - Securely store and manage passwords
- **[Password Generator](https://web-production-07c5d.up.railway.app/password-generator)** - Generate strong, customizable passwords
- **[Password Strength Checker](https://web-production-07c5d.up.railway.app/password-strength)** - Analyze password security with detailed feedback
- **[IP Lookup Tool](https://web-production-07c5d.up.railway.app/ip-lookup)** - Get comprehensive IP address information
- **[Encryption/Decryption](https://web-production-07c5d.up.railway.app/encryption)** - Secure text encryption using AES-256

### 🛡️ **Advanced Security Analysis**
- **[Hash & Checksum Analyzer](https://web-production-07c5d.up.railway.app/hash-analyzer)** - Generate and verify MD5, SHA-1, SHA-256, SHA-512 hashes
- **[Data Breach Checker](https://web-production-07c5d.up.railway.app/breach-checker)** - Check email/password breaches using HaveIBeenPwned API
- **[URL Security Scanner](https://web-production-07c5d.up.railway.app/url-scanner)** - Analyze websites for security headers and vulnerabilities

### 👥 **Authentication & User Management**
- **[User Registration](https://web-production-07c5d.up.railway.app/register)** - Create new accounts with email/password
- **[User Login](https://web-production-07c5d.up.railway.app/login)** - Secure authentication system
- **[Google OAuth](https://web-production-07c5d.up.railway.app/login)** - Sign in/up with Google account
- **[User Dashboard](https://web-production-07c5d.up.railway.app/dashboard)** - Personalized user experience
- **Session Management** - Secure login sessions with logout functionality

### 👥 **Community Features**
- **[Community Posts](https://web-production-07c5d.up.railway.app/community)** - Share experiences and learn from security community

## 📱 **Cross-Platform Access**

✅ **Desktop Browsers** (Chrome, Firefox, Safari, Edge)  
✅ **Mobile Devices** (iOS, Android)  
✅ **Tablets** (iPad, Android tablets)  
✅ **Any Operating System** (Windows, macOS, Linux)  
✅ **Global Internet Access** - No downloads required!

## 🎨 **Tech Stack**

### **Backend**
- **Python 3.9+** - Core programming language
- **Flask 2.3.3** - Web framework
- **Gunicorn** - Production WSGI server
- **Cryptography** - AES-256 encryption
- **Requests** - HTTP library for API calls

### **Frontend**
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with gradients and glassmorphism
- **Bootstrap 5.1.3** - Responsive UI framework
- **Font Awesome 6.0** - Icon library
- **Vanilla JavaScript (ES6+)** - Interactive functionality
- **Fetch API** - Asynchronous requests

### **Deployment**
- **Railway.app** - Cloud hosting platform
- **Git** - Version control
- **GitHub** - Repository hosting

## 🔒 **Security Features**

- **🔐 AES-256 Encryption** with PBKDF2 key derivation (100,000 iterations)
- **🛡️ Secure Password Storage** with industry-standard practices
- **🌐 HTTPS Enabled** for all communications
- **🔑 Environment-based Secret Keys** for production security
- **📝 Input Validation** and sanitization on all forms

## 🚀 **Quick Start**

### **Use Online (Recommended)**
Simply visit: **[https://web-production-07c5d.up.railway.app/](https://web-production-07c5d.up.railway.app/)**

No installation required! All tools work directly in your browser.

### **Run Locally**
```bash
# Clone the repository
git clone https://github.com/BSRohit20/Net-armor-.git
cd Net-armor-

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Access at: `http://localhost:5000`

## 📖 **User Guide**

### **🔑 Password Manager**
1. Navigate to [Password Manager](https://web-production-07c5d.up.railway.app/password-manager)
2. Add new passwords with website, username, and password
3. View saved passwords (click copy to clipboard)
4. All data is stored securely

### **🎲 Password Generator**
1. Go to [Password Generator](https://web-production-07c5d.up.railway.app/password-generator)
2. Set desired length (4-128 characters)
3. Choose character types (uppercase, lowercase, digits, special)
4. Generate and copy strong passwords
5. Save directly to Password Manager

### **⚡ Password Strength Checker**
1. Visit [Password Strength Checker](https://web-production-07c5d.up.railway.app/password-strength)
2. Enter any password to analyze
3. Get detailed strength assessment
4. Receive improvement recommendations
5. Real-time feedback on security requirements

### **🌐 IP Lookup Tool**
1. Access [IP Lookup](https://web-production-07c5d.up.railway.app/ip-lookup)
2. Enter any IPv4 address or click "My IP"
3. Get comprehensive information:
   - Geographic location
   - ISP and network details
   - Timezone and currency info
   - Coordinates and more

### **🔐 Encryption/Decryption**
1. Open [Encryption Tool](https://web-production-07c5d.up.railway.app/encryption)
2. **Encrypt**: Enter text and password, get encrypted output
3. **Decrypt**: Enter encrypted text and same password
4. Uses military-grade AES-256 encryption
5. Copy results to clipboard

### **💬 Community Posts**
1. Visit [Community](https://web-production-07c5d.up.railway.app/community)
2. Share security experiences and tips
3. Ask questions and learn from others
4. Real-time post updates

## 🏗️ **Project Structure**

```
NET ARMOR/
├── 📄 app.py                    # Main Flask application
├── 📄 requirements.txt          # Python dependencies
├── 📄 Procfile                 # Railway deployment config
├── 📄 render.yaml              # Render.com deployment config
├── 📄 Dockerfile               # Docker container setup
├── � docker-compose.yml       # Docker Compose setup
├── �📁 templates/               # HTML templates
│   ├── 📄 base.html            # Base template with Bootstrap
│   ├── 📄 index.html           # Homepage
│   ├── 📄 login.html           # User authentication
│   ├── 📄 register.html        # User registration
│   ├── 📄 dashboard.html       # User dashboard
│   ├── 📄 community.html       # Community posts
│   ├── 📄 toolkit.html         # Tools overview
│   ├── 📄 password_manager.html
│   ├── 📄 password_generator.html
│   ├── 📄 password_strength.html
│   ├── 📄 ip_lookup.html
│   ├── 📄 encryption.html
│   ├── � hash_analyzer.html
│   ├── 📄 breach_checker.html
│   └── 📄 url_scanner.html
├── �📁 static/                  # CSS, JS, images
├── 📁 deployment/              # Deployment scripts
│   ├── 📄 deploy.bat           # Windows deployment
│   ├── 📄 deploy-to-render.bat # Render deployment script
│   ├── 📄 one-click-deploy.bat # Automated deployment
│   └── 📄 setup-git.bat        # Git initialization
└── 📁 docs/                    # Documentation
    ├── 📄 RENDER_DEPLOYMENT_GUIDE.md
    ├── 📄 GOOGLE_OAUTH_SETUP.md
    └── 📄 EMAIL_VALIDATION_FEATURES.md
```

## � **Features Showcase**

### **🎨 Modern UI/UX**
- **Glassmorphism Design** with translucent cards
- **Gradient Backgrounds** for visual appeal
- **Responsive Layout** adapts to any screen size
- **Smooth Animations** and hover effects
- **Dark Theme** optimized for security focus

### **⚡ Performance**
- **Fast Loading** optimized for global access
- **CDN Assets** for quick resource delivery
- **Efficient APIs** with minimal data transfer
- **Responsive Design** works on slow connections

### **� Developer Features**
- **RESTful API** endpoints for all tools
- **JSON Data Storage** (easily upgradeable to database)
- **Environment Configuration** for different deployments
- **Error Handling** with user-friendly messages
- **Logging** for debugging and monitoring

## 🚀 **Quick Deploy Buttons**

Deploy NET ARMOR instantly on your preferred platform:

[![Deploy to Railway](https://railway.app/button.svg)](https://railway.app/new/template/railway)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

**One-Click Deployment Scripts:**
- 🪟 **Windows**: Run `deploy-to-render.bat`
- 🐧 **Linux/macOS**: See `RENDER_DEPLOYMENT_GUIDE.md`

---

## 🚀 **Deployment Options**

### **Current Deployment: Railway.app**
- **Live URL**: https://web-production-07c5d.up.railway.app/
- **Auto-scaling** based on traffic
- **Global CDN** for fast worldwide access
- **99.9% Uptime** guarantee
- **HTTPS SSL** certificate included

### **Alternative Deployments**

#### **🌐 Render.com Deployment**
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

**Step-by-Step Render Deployment:**

1. **Fork/Upload Repository**
   - Go to [Render.com](https://render.com) and sign up/login
   - Connect your GitHub account or upload your repository

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your NET ARMOR repository
   - Choose "main" branch

3. **Configure Deployment Settings**
   ```
   Name: net-armor-app (or your preferred name)
   Region: Choose closest to your users
   Branch: main
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: gunicorn app:app
   ```

4. **Environment Variables** (Optional)
   ```
   FLASK_ENV=production
   SECRET_KEY=your-secret-key-here
   GOOGLE_CLIENT_ID=your-google-oauth-id (if using OAuth)
   GOOGLE_CLIENT_SECRET=your-google-oauth-secret (if using OAuth)
   ```

5. **Deploy**
   - Click "Create Web Service"
   - Wait for build to complete (~2-3 minutes)
   - Your app will be live at: `https://your-app-name.onrender.com`

**Render Features:**
- ✅ **Free Tier Available** - Perfect for testing
- ✅ **Auto-deploys** from GitHub
- ✅ **SSL Certificates** included
- ✅ **Custom Domains** supported
- ✅ **Global CDN** for fast loading

#### **🚀 Other Platforms**

| Platform | Free Tier | Auto Deploy | SSL/HTTPS | Custom Domain | Database | Best For |
|----------|-----------|-------------|-----------|---------------|-----------|----------|
| **Railway** | $5 credit | ✅ | ✅ Free | ✅ Paid | 🔄 Add-ons | Current deployment |
| **Render** | 750h/month | ✅ | ✅ Free | ✅ Free | 🔄 Add-ons | **Recommended alternative** |
| **Heroku** | ❌ Discontinued | ✅ | ✅ Free | ✅ Paid | 🔄 Add-ons | Legacy apps |
| **Vercel** | ✅ Limited | ✅ | ✅ Free | ✅ Free | ❌ External | Static/Jamstack |
| **DigitalOcean** | ❌ $4/month | 🔄 Manual | 🔄 Setup | ✅ Full control | ✅ Full control | VPS control |

**💡 Recommendation**: Use **Render.com** for the best free alternative to Railway with similar features and better free tier limits.

## 🛠️ **Development Setup**

### **Prerequisites**
- Python 3.9+
- Git
- Modern web browser

### **Local Development**
```bash
# Clone repository
git clone https://github.com/BSRohit20/Net-armor-.git
cd Net-armor-

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export SECRET_KEY=your-secret-key
export FLASK_ENV=development

# Run development server
python app.py
```

### **Environment Variables**
```bash
SECRET_KEY=your-random-secret-key-here
FLASK_ENV=production  # or development
PORT=5000  # Optional, defaults to 5000
```

## 🤝 **Contributing**

We welcome contributions! Here's how to get started:

### **🐛 Bug Reports**
1. Check existing issues first
2. Create detailed bug report with steps to reproduce
3. Include browser/device information

### **✨ Feature Requests**
1. Open an issue with feature description
2. Explain use case and benefits
3. Discuss implementation approach

### **🔧 Code Contributions**
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes and test thoroughly
4. Submit pull request with description

### **📝 Documentation**
- Improve README or code comments
- Add usage examples
- Create tutorials or guides

## 📊 **API Documentation**

### **Password Generator API**
```javascript
POST /api/generate_password
{
  "length": 12,
  "uppercase": true,
  "lowercase": true,
  "digits": true,
  "special": true
}
```

### **Password Strength API**
```javascript
POST /api/check_password_strength
{
  "password": "your-password-here"
}
```

### **IP Lookup API**
```javascript
POST /api/lookup_ip
{
  "ip": "8.8.8.8"
}
```

### **Encryption API**
```javascript
POST /api/encrypt
{
  "text": "secret message",
  "password": "encryption-key"
}
```

## 🔐 **Security Considerations**

### **Data Protection**
- **No sensitive data** stored on servers
- **Client-side processing** when possible
- **Secure transmission** via HTTPS
- **Password hashing** with industry standards

### **Privacy**
- **No user tracking** or analytics
- **No data collection** beyond necessary functionality
- **No third-party integrations** that compromise privacy
- **Local storage** for temporary data only

## 📞 **Support & Contact**

### **🆘 Getting Help**
- **Issues**: [GitHub Issues](https://github.com/BSRohit20/Net-armor-/issues)
- **Discussions**: [GitHub Discussions](https://github.com/BSRohit20/Net-armor-/discussions)
- **Documentation**: This README file

### **📧 Contact**
- **Developer**: BSRohit20
- **GitHub**: [@BSRohit20](https://github.com/BSRohit20)
- **Repository**: [Net-armor-](https://github.com/BSRohit20/Net-armor-)

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## � **Acknowledgments**

- **Bootstrap Team** for the excellent UI framework
- **Font Awesome** for comprehensive icon library
- **Flask Community** for the powerful web framework
- **Railway.app** for reliable hosting platform
- **Security Community** for best practices and feedback

## 🚀 **Roadmap**

### **🔜 Upcoming Features**
- [ ] **Multi-factor Authentication** support
- [ ] **Dark/Light Theme** toggle
- [ ] **Password Import/Export** functionality
- [ ] **Advanced IP Geolocation** with maps
- [ ] **File Encryption** capabilities
- [ ] **User Accounts** with sync across devices

### **🎯 Long-term Goals**
- [ ] **Mobile Apps** (iOS/Android)
- [ ] **Browser Extensions** for password management
- [ ] **API Rate Limiting** for production scaling
- [ ] **Database Migration** from JSON to PostgreSQL
- [ ] **Advanced Analytics** dashboard
- [ ] **Enterprise Features** for organizations

---

## 🌟 **Star This Repository**

If you find NET ARMOR useful, please ⭐ **star this repository** to show your support!

**🛡️ Stay Secure, Stay Protected with NET ARMOR! 🛡️**

---

*Made with ❤️ by BSRohit20 | Deployed with 🚀 Railway.app*
