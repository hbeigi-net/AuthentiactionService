
using Application.Core;
using Application.Core.Models;
using Application.Interfaces;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Infrastructure.Services;

public class EmailService(
  ILogger<EmailService> logger,
  IOptions<EmailSettings> emailSettings
) : IEmailService
{
  private readonly EmailSettings _emailSettings = emailSettings.Value;
  private readonly ILogger<EmailService> _logger = logger;

  public async Task<bool> SendEmailAsync(EmailMessage message, CancellationToken cancellationToken = default)
  {
    try
    {
      var mimeMessage = CreateMimeMessage(message);
      var client = new SmtpClient();

      await client.ConnectAsync(
        _emailSettings.SmtpServer,
        _emailSettings.SmtpPort,
        _emailSettings.SmtpUseSsl,
        cancellationToken
      );

      await client.AuthenticateAsync(
        _emailSettings.Username,
        _emailSettings.Password,
        cancellationToken
      );

      await client.SendAsync(mimeMessage, cancellationToken);

      await client.DisconnectAsync(true, cancellationToken);

      _logger.LogInformation("Email sent successfully to {To}", message.To);
      return true;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error sending email");
      return false;
    }
  }

  private MimeMessage CreateMimeMessage(EmailMessage message)
  {
    var mimeMessage = new MimeMessage();

    mimeMessage.From.Add(
      new MailboxAddress(
        _emailSettings.FromName,
        message.From ?? _emailSettings.FromEmail
      )
    );

    mimeMessage.To.Add(MailboxAddress.Parse(message.To));

    foreach (var cc in message.Cc)
    {
      mimeMessage.Cc.Add(MailboxAddress.Parse(cc));
    }

    mimeMessage.Subject = message.Subject;

    var bodyBuilder = new BodyBuilder();
    if (message.IsHtml)
    {
      bodyBuilder.HtmlBody = message.Body;
    }
    else
    {
      bodyBuilder.TextBody = message.Body;
    }

    mimeMessage.Body = bodyBuilder.ToMessageBody();

    return mimeMessage;
  }
}