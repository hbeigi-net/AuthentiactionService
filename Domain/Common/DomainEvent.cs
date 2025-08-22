using System;

namespace Domain.Common;

public abstract class DomainEvent
{
    public Guid Id { get; protected set; } = Guid.NewGuid();
    public DateTime OccurredOn { get; protected set; } = DateTime.UtcNow;
}

