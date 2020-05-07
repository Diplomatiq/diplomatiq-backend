<p align="center">
  <img src="logo.png" width="500px">
</p>

Networking for the diplomatiq world.

[https://api.diplomatiq.org](https://api.diplomatiq.org)

<p>
<a href="https://github.com/Diplomatiq/diplomatiq-backend/actions?query=workflow%3A%22Build+and+publish+to+Azure+%28develop%29%22" target="_blank" style="text-decoration: none;">
  <img src="https://github.com/Diplomatiq/diplomatiq-backend/workflows/Build%20and%20publish%20to%20Azure%20(develop)/badge.svg" alt="build status">
</a>

<a href="https://github.com/Diplomatiq/diplomatiq-backend/actions?query=workflow%3A%22Build+and+publish+to+Azure+%production%29%22" target="_blank" style="text-decoration: none;">
  <img src="https://github.com/Diplomatiq/diplomatiq-backend/workflows/Build%20and%20publish%20to%20Azure%20(production)/badge.svg" alt="build status">
</a>

<a href="https://github.com/Diplomatiq/diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://img.shields.io/github/languages/top/Diplomatiq/diplomatiq-backend.svg" alt="languages used">
</a>
</p>

<p>
<a href="https://sonarcloud.io/dashboard?id=Diplomatiq_diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://sonarcloud.io/api/project_badges/measure?project=Diplomatiq_diplomatiq-backend&metric=alert_status" alt="Quality Gate">
</a>

<a href="https://sonarcloud.io/dashboard?id=Diplomatiq_diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://sonarcloud.io/api/project_badges/measure?project=Diplomatiq_diplomatiq-backend&metric=coverage" alt="Coverage">
</a>

<a href="https://sonarcloud.io/dashboard?id=Diplomatiq_diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://sonarcloud.io/api/project_badges/measure?project=Diplomatiq_diplomatiq-backend&metric=sqale_rating" alt="Maintainability Rating">
</a>

<a href="https://sonarcloud.io/dashboard?id=Diplomatiq_diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://sonarcloud.io/api/project_badges/measure?project=Diplomatiq_diplomatiq-backend&metric=reliability_rating" alt="Reliability Rating">
</a>

<a href="https://sonarcloud.io/dashboard?id=Diplomatiq_diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://sonarcloud.io/api/project_badges/measure?project=Diplomatiq_diplomatiq-backend&metric=security_rating" alt="Security Rating">
</a>

<a href="https://github.com/Diplomatiq/diplomatiq-backend/pulls" target="_blank" style="text-decoration: none;">
  <img src="https://api.dependabot.com/badges/status?host=github&repo=Diplomatiq/diplomatiq-backend" alt="Dependabot">
</a>
</p>

<p>
<a href="https://gitter.im/Diplomatiq/diplomatiq-backend" target="_blank" style="text-decoration: none;">
  <img src="https://badges.gitter.im/Diplomatiq/diplomatiq-backend.svg" alt="Gitter">
</a>
</p>

---

## Basics

The application is implemented with the Spring Boot framework.

After something is pushed to the `develop` branch, the branch is immediately deployed to the `develop` slot of the `diplomatiq-backend` resource in Azure: [https://api.diplomatiq.org/?x-ms-routing-name=develop](https://app.diplomatiq.org/?x-ms-routing-name=develop)

Same for the `master` branch, but after a push, the branch is deployed to the `staging` slot, which gets auto-swapped into production in order to reach the zen of zero-downtime deployment.

## OpenAPI documentation

The detailed documentation of the API is available in OpenAPI 3 format on [https://api.diplomatiq.org/openapi-documentation/v3/ui](https://api.diplomatiq.org/openapi-documentation/v3/ui). The documentation looks better in Chrome or Firefox, while for some reason, Swagger UI keeps having problems with Safari.

For client generation, the documentation is also available as a machine-readable JSON on [https://api.diplomatiq.org/openapi-documentation/v3/api](https://api.diplomatiq.org/openapi-documentation/v3/api).

## Development

See [CONTRIBUTING.md](https://github.com/Diplomatiq/diplomatiq-backend/blob/develop/CONTRIBUTING.md) for details.

---

Copyright (c) 2018 Diplomatiq
