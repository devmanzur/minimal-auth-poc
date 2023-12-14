using System.Text.Json;
using FluentValidation;
using IdentityServer.Shared.Contracts;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Shared.Handlers;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly Dictionary<Type, Func<HttpContext, Exception, Task>> _exceptionHandlers;

    public GlobalExceptionHandler()
    {
        // Register known exception types and handlers.
        _exceptionHandlers = new()
        {
            { typeof(ValidationException), HandleValidationException },
            { typeof(UnauthorizedAccessException), HandleUnauthorizedAccessException },
            { typeof(BadHttpRequestException), HandleBadRequestException },
            { typeof(InvalidOperationException), HandleInvalidOperationException }
        };
    }

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception,
        CancellationToken cancellationToken)
    {
        var exceptionType = exception.GetType();

        if (_exceptionHandlers.TryGetValue(exceptionType, out var handler))
        {
            await handler.Invoke(httpContext, exception);
            return true;
        }

        return false;
    }

    private async Task HandleBadRequestException(HttpContext httpContext, Exception ex)
    {
        var exception = (BadHttpRequestException)ex;
        if (exception.InnerException?.GetType() == typeof(JsonException))
        {
            // Handle JSON deserialization exceptions
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;

            var problem = new ProblemDetails()
            {
                Status = StatusCodes.Status422UnprocessableEntity,
                Type = "https://datatracker.ietf.org/doc/html/rfc4918#section-11.2",
                Detail = exception.InnerException!.Message,
            };

            await httpContext.Response.WriteAsJsonAsync(new Envelope<object>(null, null, problem, DateTimeOffset.UtcNow,
                Guid.NewGuid().ToString()));
        }
    }

    private async Task HandleValidationException(HttpContext httpContext, Exception ex)
    {
        var exception = (ValidationException)ex;

        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        
        var errors = exception.Errors
            .GroupBy(e => e.PropertyName, e => e.ErrorMessage)
            .ToDictionary(failureGroup => failureGroup.Key, failureGroup => failureGroup.ToArray());

        var problem = new ValidationProblemDetails(errors)
        {
            Status = StatusCodes.Status400BadRequest,
            Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1"
        };

        await httpContext.Response.WriteAsJsonAsync(new Envelope<object, ValidationProblemDetails>(null, null, problem,
            DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString()));
    }

    private async Task HandleUnauthorizedAccessException(HttpContext httpContext, Exception ex)
    {
        httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;

        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status401Unauthorized,
            Type = "https://tools.ietf.org/html/rfc7235#section-3.1"
        };

        await httpContext.Response.WriteAsJsonAsync(new Envelope<object>(null, null, problem, DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString()));
    }

    private async Task HandleInvalidOperationException(HttpContext httpContext, Exception ex)
    {
        var requestType = httpContext.Request.Method;

        // default
        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status422UnprocessableEntity,
            Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            Title = "Action not allowed",
            Detail = "The resource does not exist or does not allow the requested action"
        };

        if (requestType == HttpMethods.Get)
        {
            problemDetails.Status = StatusCodes.Status404NotFound;
            problemDetails.Type = "https://tools.ietf.org/html/rfc7231#section-6.5.4";
            problemDetails.Title = "Resource not found";
            problemDetails.Detail = "The resource does not exist";
        }

        httpContext.Response.StatusCode = (int)problemDetails.Status;

        await httpContext.Response.WriteAsJsonAsync(new Envelope<object>(null, null, problemDetails,
            DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString()));
    }
}
