
using SecureMessaging.Api.Services;
using SecureMessaging.Core.Services;

var builder = WebApplication.CreateBuilder(args);

// Register application services
builder.Services.AddSingleton<IRsaService, RsaService>();
builder.Services.AddSingleton<IAesService, AesService>();

builder.Services.AddSingleton<RsaKeyStore>();
builder.Services.AddSingleton<AesSessionStore>();

// Register controllers and Swagger
builder.Services.AddControllers();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Enable Swagger in development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.MapControllers();

app.Run();
