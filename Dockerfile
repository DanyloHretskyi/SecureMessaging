
# Build the application using the .NET 10 SDK
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

# Copy project files and restore dependencies
COPY ["SecureMessaging.Api/SecureMessaging.Api.csproj", "SecureMessaging.Api/"]
COPY ["SecureMessaging.Core/SecureMessaging.Core.csproj", "SecureMessaging.Core/"]

RUN dotnet restore "SecureMessaging.Api/SecureMessaging.Api.csproj"

# Copy source code and publish the API
COPY . .

RUN dotnet publish "SecureMessaging.Api/SecureMessaging.Api.csproj" \
    -c Release \
    -o /app/publish \
    --no-restore

# Use the smaller ASP.NET Core runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final

WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "SecureMessaging.Api.dll"]
