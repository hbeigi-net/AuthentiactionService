
using FluentResults;

namespace Application.Core;

public class ApplicationResult<T>
{
  public uint StatusCode { get; set; } = 200;
  public T? Value { get; set; }
  public string? ErrorMessage { get; set; }
  public bool IsSuccess {get;set;}
  public bool IsFailed  => !IsSuccess;
  public string? RedirectUrl { get; set; }

  public Dictionary<string, string[]>[]? Errors { get; set; } = [];

  public static ApplicationResult<T> Ok(T value, uint statusCode = 200){
    return new ApplicationResult<T>{
      Value = value,
      StatusCode = statusCode,
      IsSuccess = true,
    };
  }

  public static ApplicationResult<T> Fail(string errorMessage, uint statusCode = 400){
    return new ApplicationResult<T>{
      ErrorMessage = errorMessage,
      StatusCode = statusCode,
      IsSuccess = false,
    };
  }

  public static ApplicationResult<T> Redirect(string redirectUrl, uint statusCode = 302){
    return new ApplicationResult<T>{
      RedirectUrl = redirectUrl,
      StatusCode = statusCode,
      IsSuccess = true,
    };
  }
}