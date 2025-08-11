using System;

namespace Domain.Common;

public interface IAuditableEntity
{
  DateTime CreatedAt { get; set; }
  string CreatedBy { get; set; }
  DateTime? UpdatedAt { get; set; }
  string? UpdatedBy { get; set; }
}

public abstract class DomainEvent
{
    public Guid Id { get; protected set; } = Guid.NewGuid();
    public DateTime OccurredOn { get; protected set; } = DateTime.UtcNow;
}
