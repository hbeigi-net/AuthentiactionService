
using Application.Core.Models;

namespace Application.Interfaces;

public interface IEmailTemplateService
{
  EmailMessage GetEmailVerificationTemplate(string email, string token);
  EmailMessage GetResetPasswordTemplate(string email, string token);
}