
namespace Application.Core.Models;

public class EmailMessage
{
  public string To { get; set; } = string.Empty;
  public string Subject { get; set; } = string.Empty;
  public string Body { get; set; } = string.Empty;
  public string? From { get; set; }
  public List<string> Cc { get; set; } = new();
  public List<EmailAttachment> Attachments { get; set; } = new();
  public bool IsHtml { get; set; } = true;
}