using System.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace IdentityEndpoints.Shared.Contracts;

public record Envelope<T>(T? Data, object? Meta = null, ProblemDetails? Problem = null, DateTimeOffset? Timestamp = null, string? TraceId = null);
public record Envelope<T, E>(T? Data, object? Meta = null, E? Problem = null, DateTimeOffset? Timestamp = null, string? TraceId = null)
    where E : ProblemDetails;

public static class Envelope
{
    public static Ok<Envelope<T>> Success<T>(T? body, object? meta = null)
    {
        return TypedResults.Ok(new Envelope<T>(body, meta, null, DateTimeOffset.UtcNow, Guid.NewGuid().ToString()));
    }

    public static JsonHttpResult<Envelope<object>> NotFound()
    {
        return TypedResults.Json(
            new Envelope<object>(null, null, new ProblemDetails()
            {
                Status = StatusCodes.Status404NotFound,
                Type = "https://tools.ietf.org/html/rfc7231#section-6.5.4",
                Title = "Resource not found",
                Detail = "The resource does not exist"
            }, DateTimeOffset.UtcNow, Guid.NewGuid().ToString()),
            statusCode: (int)HttpStatusCode.BadRequest, contentType: "application/json");
    }
}
