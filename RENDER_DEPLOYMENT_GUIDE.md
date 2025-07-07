# 🌐 Render.com Deployment Guide for NET ARMOR

This guide provides detailed step-by-step instructions for deploying NET ARMOR on Render.com, a modern cloud platform that offers free hosting with automatic deployments.

## 📋 **Prerequisites**

- GitHub account with NET ARMOR repository
- Render.com account (free signup)
- Basic understanding of web deployment

## 🚀 **Step-by-Step Deployment**

### **Step 1: Prepare Your Repository**

1. **Ensure all files are committed and pushed to GitHub:**
   ```bash
   git add .
   git commit -m "Prepare for Render deployment"
   git push origin main
   ```

2. **Verify required files exist:**
   - ✅ `requirements.txt` - Python dependencies
   - ✅ `app.py` - Main Flask application
   - ✅ `Procfile` - Web server configuration (optional for Render)

### **Step 2: Create Render Account**

1. **Go to [render.com](https://render.com)**
2. **Sign up** using GitHub, GitLab, or email
3. **Connect your GitHub account** for easy repository access

### **Step 3: Create New Web Service**

1. **Click "New +"** in the Render dashboard
2. **Select "Web Service"**
3. **Connect your repository:**
   - If GitHub connected: Select your NET ARMOR repository
   - If not connected: Upload repository or connect GitHub

### **Step 4: Configure Deployment Settings**

Fill out the deployment form with these settings:

#### **Basic Settings:**
```
Name: net-armor-security-toolkit
Region: Oregon (US West) or closest to your users
Branch: main
Runtime: Python 3
```

#### **Build & Deploy Settings:**
```
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app --host 0.0.0.0 --port $PORT
```

#### **Pricing:**
- Select **"Free"** for testing (includes 750 hours/month)
- Upgrade to **"Starter"** ($7/month) for production use

### **Step 5: Environment Variables (Optional)**

Add these environment variables in the "Environment" section:

#### **Required for Production:**
```
FLASK_ENV=production
SECRET_KEY=your-super-secret-key-change-this-in-production
```

#### **Optional - Google OAuth (if using):**
```
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
```

#### **Optional - Custom Settings:**
```
FLASK_DEBUG=False
PYTHONUNBUFFERED=1
```

### **Step 6: Deploy Your Application**

1. **Click "Create Web Service"**
2. **Wait for deployment** (usually 2-5 minutes)
3. **Monitor the build logs** for any errors
4. **Once deployed**, your app will be available at:
   `https://your-app-name.onrender.com`

## 🔧 **Post-Deployment Configuration**

### **Custom Domain (Optional)**
1. Go to your service settings
2. Click "Custom Domains"
3. Add your domain name
4. Configure DNS records as instructed

### **Environment Variables Updates**
1. Go to service settings
2. Click "Environment"
3. Add/modify variables as needed
4. Service will auto-redeploy

### **Monitoring & Logs**
1. **View logs**: Service dashboard → "Logs" tab
2. **Monitor metrics**: Service dashboard → "Metrics" tab
3. **Health checks**: Automatic endpoint monitoring

## 🛠️ **Troubleshooting Common Issues**

### **Build Failures**
```bash
# If requirements.txt issues:
pip freeze > requirements.txt
git add requirements.txt
git commit -m "Update requirements"
git push
```

### **App Won't Start**
- Check if `gunicorn` is in requirements.txt
- Verify app.py has the correct Flask app instance
- Check environment variables are set correctly

### **Memory/Resource Issues**
- Free tier has limited resources
- Consider upgrading to Starter plan
- Optimize your application code

### **Database Issues**
- For persistent data, use Render's PostgreSQL addon
- JSON files (users.json, etc.) reset on each deployment
- Consider external database services

## 📊 **Render.com Features & Benefits**

### **Free Tier Includes:**
- ✅ 750 hours/month (enough for most personal projects)
- ✅ SSL certificates (HTTPS)
- ✅ Automatic deployments from GitHub
- ✅ Custom domains support
- ✅ Global CDN

### **Paid Plans Offer:**
- 🚀 Always-on services (no sleep)
- 🚀 More memory and CPU
- 🚀 Priority support
- 🚀 Advanced metrics

### **Auto-Deployment**
- Automatically deploys when you push to GitHub
- No manual deployment needed after initial setup
- Rollback capabilities

## 🔄 **Updating Your Deployed App**

1. **Make changes to your code locally**
2. **Commit and push to GitHub:**
   ```bash
   git add .
   git commit -m "Update feature X"
   git push origin main
   ```
3. **Render automatically detects changes and redeploys**
4. **Monitor deployment in Render dashboard**

## 🆚 **Render vs Other Platforms**

| Feature | Render | Railway | Heroku | Vercel |
|---------|--------|---------|--------|--------|
| Free Tier | ✅ 750h/month | ✅ $5 credit | ❌ Discontinued | ✅ Limited |
| Auto Deploy | ✅ | ✅ | ✅ | ✅ |
| SSL/HTTPS | ✅ Free | ✅ Free | ✅ Free | ✅ Free |
| Custom Domains | ✅ Free | ✅ Paid | ✅ Paid | ✅ Free |
| Database | 🔄 Add-ons | 🔄 Add-ons | 🔄 Add-ons | ❌ External |

## 📞 **Support & Resources**

- **Render Documentation**: [render.com/docs](https://render.com/docs)
- **Community Forum**: [community.render.com](https://community.render.com)
- **Status Page**: [status.render.com](https://status.render.com)
- **Support**: Available through dashboard

## 🎯 **Quick Deploy Button**

Add this to your repository README for one-click deployment:

```markdown
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)
```

---

**🎉 Congratulations!** Your NET ARMOR security toolkit is now deployed on Render and accessible worldwide! 

**Example Live URL**: `https://net-armor-security-toolkit.onrender.com`

For any deployment issues, refer to the troubleshooting section above or check the Render community forums.
