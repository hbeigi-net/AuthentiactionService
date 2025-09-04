using System.Text;
using Application.Core.Models;
using Application.Interfaces;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;

namespace Infrastructure.Services;

public class EmailTemplateService(
  IConfiguration configuration
) : IEmailTemplateService
{

    private readonly IConfiguration _config = configuration;
    public EmailMessage GetEmailVerificationTemplate(string email, string token)
    {
        var verificationToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var verificationLink = $"{_config["ClientOptions:ClientUrl"]}{_config["VerificationPath"]}?email={email}&token={verificationToken}";

        return new EmailMessage
        {
            To = email,
            Subject = "Welcome to our app",
            Body = $$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verification</title>
                    <style>
                        * {
                            margin: 0;
                            padding: 0;
                            box-sizing: border-box;
                        }
                        
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.6;
                            color: #333;
                            background-color: #f4f4f4;
                        }
                        
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #ffffff;
                            border-radius: 8px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                        
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 30px 20px;
                            text-align: center;
                        }
                        
                        .header h1 {
                            font-size: 28px;
                            font-weight: 600;
                            margin-bottom: 10px;
                        }
                        
                        .header p {
                            font-size: 16px;
                            opacity: 0.9;
                        }
                        
                        .content {
                            padding: 40px 30px;
                        }
                        
                        .welcome-text {
                            font-size: 18px;
                            color: #2c3e50;
                            margin-bottom: 25px;
                            text-align: center;
                        }
                        
                        .verification-button {
                            display: inline-block;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            text-decoration: none;
                            padding: 15px 30px;
                            border-radius: 25px;
                            font-weight: 600;
                            font-size: 16px;
                            margin: 20px 0;
                            text-align: center;
                            transition: all 0.3s ease;
                            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                        }
                        
                        .verification-button:hover {
                            transform: translateY(-2px);
                            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
                        }
                        
                        .info-text {
                            background-color: #f8f9fa;
                            border-left: 4px solid #667eea;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 0 4px 4px 0;
                        }
                        
                        .footer {
                            background-color: #f8f9fa;
                            padding: 20px 30px;
                            text-align: center;
                            border-top: 1px solid #e9ecef;
                        }
                        
                        .footer p {
                            color: #6c757d;
                            font-size: 14px;
                            margin-bottom: 10px;
                        }
                        
                        .security-note {
                            background-color: #fff3cd;
                            border: 1px solid #ffeaa7;
                            border-radius: 4px;
                            padding: 15px;
                            margin: 20px 0;
                            color: #856404;
                        }
                        
                        @media only screen and (max-width: 600px) {
                            .email-container {
                                margin: 10px;
                                border-radius: 4px;
                            }
                            
                            .header {
                                padding: 20px 15px;
                            }
                            
                            .header h1 {
                                font-size: 24px;
                            }
                            
                            .content {
                                padding: 25px 20px;
                            }
                            
                            .verification-button {
                                padding: 12px 25px;
                                font-size: 14px;
                            }
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>🎉 Welcome!</h1>
                            <p>Thank you for joining our community</p>
                        </div>
                        
                        <div class="content">
                            <div class="welcome-text">
                                <p>Hi there! 👋</p>
                                <p>We're excited to have you on board. To get started, please verify your email address by clicking the button below.</p>
                            </div>
                            
                            <div style="text-align: center;">
                                <a href="{{verificationLink}}" class="verification-button">
                                    ✅ Verify Email Address
                                </a>
                            </div>
                            
                            <div class="info-text">
                                <strong>What happens next?</strong><br>
                                After verifying your email, you'll have full access to all our features and services.
                            </div>
                            
                            <div class="security-note">
                                <strong>🔒 Security Note:</strong> If you didn't create an account with us, please ignore this email. Your account security is important to us.
                            </div>
                        </div>
                        
                        <div class="footer">
                            <p>This email was sent to you because you signed up for our service.</p>
                            <p>If you have any questions, please don't hesitate to contact our support team.</p>
                            <p style="margin-top: 15px; font-size: 12px; color: #adb5bd;">
                                © 2024 Your App Name. All rights reserved.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                """
        };
    }

    public EmailMessage GetResetPasswordTemplate(string email, string token)
    {
        var resetPasswordLink = $"{_config["ClientOptions:ClientUrl"]}{_config["ResetPasswordPath"]}?email={email}&token={token}";

        return new EmailMessage
        {
            To = email,
            Subject = "Reset Password",
            Body = $$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Reset Your Password</title>
                    <style>
                        * {
                            margin: 0;
                            padding: 0;
                            box-sizing: border-box;
                        }
                        
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.6;
                            color: #333;
                            background-color: #f8f9fa;
                        }
                        
                        .container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #ffffff;
                            border-radius: 12px;
                            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                            overflow: hidden;
                        }
                        
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            padding: 40px 30px;
                            text-align: center;
                            color: white;
                        }
                        
                        .header h1 {
                            font-size: 28px;
                            font-weight: 600;
                            margin-bottom: 10px;
                        }
                        
                        .header p {
                            font-size: 16px;
                            opacity: 0.9;
                        }
                        
                        .content {
                            padding: 40px 30px;
                            text-align: center;
                        }
                        
                        .icon {
                            width: 80px;
                            height: 80px;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            border-radius: 50%;
                            margin: 0 auto 30px;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            font-size: 36px;
                            color: white;
                        }
                        
                        .title {
                            font-size: 24px;
                            font-weight: 600;
                            color: #2d3748;
                            margin-bottom: 20px;
                        }
                        
                        .description {
                            font-size: 16px;
                            color: #718096;
                            margin-bottom: 35px;
                            line-height: 1.7;
                        }
                        
                        .reset-button {
                            display: inline-block;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            text-decoration: none;
                            padding: 16px 40px;
                            border-radius: 50px;
                            font-size: 16px;
                            font-weight: 600;
                            margin-bottom: 30px;
                            transition: all 0.3s ease;
                            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                        }
                        
                        .reset-button:hover {
                            transform: translateY(-2px);
                            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
                        }
                        
                        .info-box {
                            background-color: #f7fafc;
                            border: 1px solid #e2e8f0;
                            border-radius: 8px;
                            padding: 20px;
                            margin-bottom: 30px;
                        }
                        
                        .info-box h3 {
                            color: #2d3748;
                            font-size: 16px;
                            margin-bottom: 10px;
                        }
                        
                        .info-box p {
                            color: #718096;
                            font-size: 14px;
                            margin-bottom: 8px;
                        }
                        
                        .footer {
                            background-color: #f8f9fa;
                            padding: 30px;
                            text-align: center;
                            border-top: 1px solid #e2e8f0;
                        }
                        
                        .footer p {
                            color: #a0aec0;
                            font-size: 14px;
                            margin-bottom: 10px;
                        }
                        
                        .footer .contact {
                            color: #667eea;
                            text-decoration: none;
                        }
                        
                        .footer .contact:hover {
                            text-decoration: underline;
                        }
                        
                        @media (max-width: 600px) {
                            .container {
                                margin: 10px;
                                border-radius: 8px;
                            }
                            
                            .header, .content, .footer {
                                padding: 30px 20px;
                            }
                            
                            .header h1 {
                                font-size: 24px;
                            }
                            
                            .title {
                                font-size: 20px;
                            }
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 Password Reset</h1>
                            <p>Secure your account with a new password</p>
                        </div>
                        
                        <div class="content">
                            <div class="icon">🔑</div>
                            
                            <h2 class="title">Reset Your Password</h2>
                            <p class="description">
                                We received a request to reset your password. Click the button below to create a new secure password for your account.
                            </p>
                            
                            <a href="{{resetPasswordLink}}" class="reset-button">
                                Reset Password
                            </a>
                            
                            <div class="info-box">
                                <h3>⚠️ Important Information</h3>
                                <p>• This link will expire in 15 minutes for security</p>
                                <p>• If you didn't request this, please ignore this email</p>
                                <p>• Your password will remain unchanged until you click the link above</p>
                            </div>
                            
                            <p style="color: #718096; font-size: 14px;">
                                Having trouble? Copy and paste this link into your browser:<br>
                                <span style="color: #667eea; word-break: break-all;">{{resetPasswordLink}}</span>
                            </p>
                        </div>
                        
                        <div class="footer">
                            <p>This is an automated message, please do not reply to this email.</p>
                            <p>If you need assistance, contact our support team at <a href="mailto:support@yourapp.com" class="contact">support@yourapp.com</a></p>
                            <p style="margin-top: 20px; font-size: 12px; color: #cbd5e0;">
                                © 2024 Your App Name. All rights reserved.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                """
        };
    }
}
