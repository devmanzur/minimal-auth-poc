using IdentityServer.Configurations;
using IdentityServer.Endpoints;
using IdentityServer.Shared.Handlers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.OperationFilter<Vernou.Swashbuckle.HttpResultsAdapter.HttpResultsOperationFilter>();
});
builder.Services.AddRouting(options =>
{
    options.LowercaseUrls = true;
    options.LowercaseQueryStrings = true;
});
// Setup OpenIddict
builder.Services.ConfigureIdentityServer(builder.Configuration);
builder.Services.AddDistributedMemoryCache();
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
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapIdentityEndpoints();
app.MapAccountEndpoints();

app.Run();