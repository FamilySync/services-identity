FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG version
ARG username
ARG token
WORKDIR /src

RUN echo "machine github.com login $username $token" > ~/.netrc
RUN echo "machine api.github.com login $username password $token" >> ~/.netrc

RUN chmod 600 ~/.netrc

COPY ["FamilySync.Services.Identity/FamilySync.Services.Identity.csproj", "FamilySync.Services.Identity/"]
COPY ["NuGet.config", "FamilySync.Services.Identity/"]

RUN dotnet restore "FamilySync.Services.Identity/FamilySync.Services.Identity.csproj" --configfile FamilySync.Services.Identity/NuGet.config

COPY . .

RUN dotnet publish "FamilySync.Services.Identity/FamilySync.Services.Identity.csproj" -c Release -o out /p:Version=$version

FROM mcr.microsoft.com/dotnet/aspnet:8.0 
WORKDIR /app

EXPOSE 80
EXPOSE 443

COPY --from=build /src/out .
ENTRYPOINT ["dotnet", "FamilySync.Services.Identity.dll"]
