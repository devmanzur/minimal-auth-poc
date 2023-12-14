using IdentityEndpoints.Brokers.Database;
using IdentityEndpoints.Domain.Models;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();
builder.Services.AddDbContext<AppIdentityDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("AuthDatabase")));
builder.Services
    .AddIdentityApiEndpoints<ApplicationUser>()
    .AddEntityFrameworkStores<AppIdentityDbContext>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/weatherforecast", () => "Welcome!!")
    .WithName("GetWeatherForecast")
    .RequireAuthorization() // 👈 Add this
    .WithOpenApi();

app.MapGroup("/identity").MapIdentityApi<ApplicationUser>();

app.Run();