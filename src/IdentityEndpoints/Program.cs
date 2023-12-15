using IdentityEndpoints.Configurations;
using IdentityEndpoints.Domain.Models;
using IdentityEndpoints.Endpoints;
using IdentityEndpoints.Shared.Handlers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.ConfigureIdentityServer(builder.Configuration);
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler(_ => { });

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapIdentityEndpoints();
app.MapAccountEndpoints();

app.Run();