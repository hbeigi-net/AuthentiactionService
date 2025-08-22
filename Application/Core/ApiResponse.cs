using System;

namespace Application.Core;

public class ApiResponse<T>
{
  public bool IsSuccess { get; set; }
  public T? Result { get; set; }

  public string? ErrorMessage { get; set; }
  public string? StackTrace { get; set; } = null;

}
