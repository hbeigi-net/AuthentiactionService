
namespace Application.Core;

public class EmailSettings {
  public required string SmtpServer {get;set;}
  public int SmtpPort {get;set;}
  public required string Username {get;set;}
  public required string Password {get;set;}
}