using System;

namespace Domain.Events;

public class UserLoggedInEvent
{
  public Guid UserId { get; }
  public string IpAddress { get; }
  public string DeviceInfo { get; }

  public UserLoggedInEvent(Guid userId, string ipAddress, string deviceInfo)
  {
    UserId = userId;
    IpAddress = ipAddress;
    DeviceInfo = deviceInfo;
  }
}
