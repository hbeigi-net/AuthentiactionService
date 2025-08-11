using System;

namespace Domain.Events;

public class UserRegisteredEvent
{
  public Guid UserId { get; }
  public string Email { get; }
  public string FullName { get; }

  public UserRegisteredEvent(Guid userId, string email, string fullName)
  {
    UserId = userId;
    Email = email;
    FullName = fullName;
  }
}
