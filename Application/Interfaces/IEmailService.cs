
using Application.Core.Models;

namespace Application.Interfaces;

public interface IEmailService 
{
  Task<bool> SendEmailAsync(EmailMessage message, CancellationToken cancellationToken = default);
}