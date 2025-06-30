# NET ARMOR Web Application

This is the web version of your NET ARMOR desktop application, converted to run in a web browser with **global deployment capabilities**.

## Features

- **Community Posts**: Share and read community posts
- **Password Manager**: Store and manage passwords securely  
- **Password Generator**: Generate strong passwords with customizable options
- **Password Strength Checker**: Analyze password strength with detailed feedback
- **IP Lookup**: Get detailed information about IP addresses
- **Encryption/Decryption**: Secure text encryption using AES-256

## 🌍 Global Deployment Options

### Quick Start - Choose Your Deployment Method

Run the deployment helper:
- **Windows**: Double-click `deploy.bat`
- **Linux/Mac**: Run `bash deploy.sh`

### 🚀 Option 1: Heroku (Recommended - Free Tier Available)

**Fastest way to get online globally:**

1. **Install Heroku CLI**: https://devcenter.heroku.com/articles/heroku-cli
2. **Create Heroku account**: https://signup.heroku.com/
3. **Deploy commands**:
```bash
# Login to Heroku
heroku login

# Initialize git repository
git init
git add .
git commit -m "Initial deployment"

# Create Heroku app (replace 'your-app-name' with your chosen name)
heroku create your-netarmor-app

# Set production environment variables
heroku config:set SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
heroku config:set FLASK_ENV=production

# Deploy to Heroku
git push heroku main
```

**Your app will be live at**: `https://your-netarmor-app.herokuapp.com`

### ☁️ Option 2: Railway.app (Easiest - Auto-deployment)

1. Visit https://railway.app/
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your NET ARMOR repository
5. Railway auto-detects Flask and deploys automatically
6. Set environment variables in Railway dashboard:
   - `SECRET_KEY`: Generate a random key
   - `FLASK_ENV`: production

**Result**: Automatic subdomain like `netarmor-production.up.railway.app`

### 🌊 Option 3: DigitalOcean App Platform

1. Visit https://cloud.digitalocean.com/apps
2. Click "Create App"
3. Connect your GitHub repository
4. DigitalOcean auto-detects Python/Flask
5. Configure environment variables
6. Deploy (Cost: ~$5/month)

### 🐳 Option 4: Docker Deployment

**For any VPS or cloud provider:**

```bash
# Build Docker image
docker build -t netarmor .

# Run container
docker run -p 5000:5000 -e SECRET_KEY=your-secret-key netarmor

# Or use Docker Compose
docker-compose up -d
```

### 📦 Option 5: Traditional VPS/Server

**Ubuntu/Debian VPS:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install requirements
sudo apt install python3 python3-pip nginx -y

# Clone and setup
git clone <your-repo-url>
cd NET-ARMOR
pip3 install -r requirements.txt

# Set environment variables
export SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export FLASK_ENV=production

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 app:app
```

## 🔧 Local Development

### Install and Run Locally

```powershell
# Install dependencies
pip install -r requirements.txt

# Run development server
python app.py
```

**Access at**: `http://localhost:5000`

### Easy Start (Windows)
Double-click `start.bat` - automatically installs dependencies and starts the server.

## 🔒 Production Security Checklist

- ✅ Change `SECRET_KEY` to a random value
- ✅ Set `FLASK_ENV=production`
- ✅ Use HTTPS (Let's Encrypt for free SSL)
- ✅ Configure rate limiting
- ✅ Regular data backups
- ✅ Monitor application logs

## 📁 File Structure

```
NET ARMOR/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── Procfile                 # Heroku deployment config
├── Dockerfile               # Docker container config
├── docker-compose.yml       # Docker Compose config
├── deploy.bat               # Windows deployment helper
├── deploy.sh                # Linux/Mac deployment helper
├── start.bat                # Local development starter
├── .gitignore               # Git ignore rules
├── templates/               # HTML templates
│   ├── base.html           # Base template with Bootstrap
│   ├── index.html          # Homepage
│   ├── community.html      # Community posts
│   ├── toolkit.html        # Toolkit main page
│   ├── password_manager.html
│   ├── password_generator.html
│   ├── password_strength.html
│   ├── ip_lookup.html
│   └── encryption.html
├── community_posts.json    # Community posts storage (auto-created)
└── passwords.json          # Password storage (auto-created)
```

## 🌐 Domain Setup (Optional)

Once deployed, you can connect a custom domain:

### Heroku Custom Domain
```bash
heroku domains:add www.yournetarmor.com
heroku certs:auto:enable
```

### Railway Custom Domain
- Go to Railway dashboard
- Settings → Domain
- Add your custom domain
- Update DNS records as shown

## 💾 Data Persistence

The application uses JSON file storage by default. For production with multiple users, consider upgrading to:

- **PostgreSQL** (supported by all platforms)
- **MongoDB** (for document storage)
- **SQLite** (simple file-based database)

Example PostgreSQL upgrade:
```python
pip install psycopg2-binary flask-sqlalchemy
# Update app.py to use database instead of JSON files
```

## 🚀 Performance Optimization

For high-traffic deployment:

1. **Use Redis for session storage**
2. **Add rate limiting** with Flask-Limiter
3. **Enable caching** with Flask-Caching
4. **Use CDN** for static assets
5. **Database connection pooling**

## 🆘 Troubleshooting

### Common Issues:

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**"Port already in use":**
```bash
# Kill process using port 5000
# Windows: netstat -ano | findstr :5000
# Linux: lsof -ti:5000 | xargs kill -9
```

**Deployment fails:**
- Check all files are committed to git
- Verify Procfile exists and is correct
- Ensure requirements.txt is up to date

## 📞 Support

- Check deployment logs on your platform
- Verify environment variables are set
- Ensure your chosen app name is unique
- Test locally first before deploying

## 🎯 Next Steps After Deployment

1. **Share your URL** with users globally
2. **Monitor usage** through platform dashboards
3. **Set up monitoring** and alerts
4. **Regular updates** and maintenance
5. **User feedback** and feature improvements

Your NET ARMOR toolkit is now ready for global access! 🌍🛡️
