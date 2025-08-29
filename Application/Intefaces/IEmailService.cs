
using Application.Core.Models;

namespace Application.Intefaces;

public interface IEmailService 
{
  Task<bool> SendEmailAsync(EmailMessage message, CancellationToken cancellationToken = default);
}