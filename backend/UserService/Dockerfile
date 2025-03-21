# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the entire solution
COPY . .

# Restore dependencies using solution file with --force to ignore conflicts
RUN dotnet restore UserService.sln --force

# Build the API project directly instead of the solution
RUN dotnet build UserService.API/UserService.API.csproj -c Release --no-restore -o /app/build

# Publish stage
FROM build AS publish
WORKDIR "/src"
RUN dotnet publish UserService.API/UserService.API.csproj -c Release --no-restore -o /app/publish /p:UseAppHost=false

# Final stage - using SDK image to ensure migration tools are available
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS final
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

# Create entrypoint script
RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    echo 'until pg_isready -h postgres -p 5432 -U postgres; do' >> /app/entrypoint.sh && \
    echo '  echo "Waiting for postgres to be ready..."' >> /app/entrypoint.sh && \
    echo '  sleep 2' >> /app/entrypoint.sh && \
    echo 'done' >> /app/entrypoint.sh && \
    echo 'dotnet UserService.API.dll' >> /app/entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Expose the port the app runs on
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]