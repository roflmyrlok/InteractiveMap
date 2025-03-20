# Build stage
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the entire solution
COPY . .

# Restore dependencies using solution file
RUN dotnet restore LocationService.sln

# Build the API project directly instead of the solution
RUN dotnet build LocationService.API/LocationService.API.csproj -c Release -o /app/build

# Publish stage
FROM --platform=linux/amd64 build AS publish
WORKDIR "/src"
RUN dotnet publish LocationService.API/LocationService.API.csproj -c Release -o /app/publish /p:UseAppHost=false

# Final stage - using SDK image to ensure migration tools are available
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0 AS final
WORKDIR /app

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Development
ENV ASPNETCORE_HTTP_PORTS=8080

# Install postgresql-client for database connection checks
RUN apt-get update && \
    apt-get install -y postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Copy entire solution
COPY --from=publish /src .
COPY --from=publish /app/publish .

# Install dotnet-ef tool globally
RUN dotnet tool install --global dotnet-ef

# Add dotnet tools to PATH
ENV PATH="${PATH}:/root/.dotnet/tools"

# Create entrypoint script directly with proper line endings
RUN printf '#!/bin/bash\n\
until pg_isready -h postgres -p 5432 -U postgres; do\n\
  echo "Waiting for postgres to be ready..."\n\
  sleep 2\n\
done\n\
dotnet LocationService.API.dll\n' > /app/entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Expose the port the app runs on
EXPOSE 8080

# Set the entrypoint using shell format
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]