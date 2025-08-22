using System;
using FluentResults;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.Logging;
namespace Application.Core;

public class ValidationInteceptor<TRequest, TResponse>(
  IServiceProvider serviceProvider, 
  ILogger<ValidationInteceptor<TRequest, TResponse>> logger
): IPipelineBehavior<TRequest, TResponse>
  where TRequest : notnull
{
  private readonly IServiceProvider _serviceProvider = serviceProvider;
  private readonly ILogger<ValidationInteceptor<TRequest, TResponse>> _logger = logger;
  public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
  {
    IValidator<TRequest>? validator;
    try {
      validator = _serviceProvider.GetService(typeof(IValidator<TRequest>))! as IValidator<TRequest>;
    }
    catch (Exception)
    {
      _logger.LogError("No validator found for request {RequestType}", typeof(TRequest).Name);
      validator = null;
    }
    
    if(validator == null){
      return await next(cancellationToken);
    }

    var validationResult = validator.Validate(request);
    if (!validationResult.IsValid)
    {
      throw new ValidationException(validationResult.Errors);
    }
    
    return await next(cancellationToken);
  }
}
