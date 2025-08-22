using System;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Presentation.Controllers;

[ApiController]
[Route("v{version:apiVersion}/[controller]")]
public class BaseController() : ControllerBase
{
  private IMediator? _mediator;

  protected IMediator Mediator => _mediator
    ??= HttpContext.RequestServices.GetService<IMediator>()
    ?? throw new ArgumentException("MediatR not Found");


}
