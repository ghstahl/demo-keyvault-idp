ARG build_image
FROM mcr.microsoft.com/dotnet/core/aspnet:3.0.0-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443


FROM $build_image AS build
WORKDIR /src
RUN dotnet publish demo-oidc-web-client -c Release -o out --no-restore --no-build

FROM base AS final
WORKDIR /app
COPY --from=build /src/out .
ENTRYPOINT ["dotnet", "demo-oidc-web-client.dll"]
